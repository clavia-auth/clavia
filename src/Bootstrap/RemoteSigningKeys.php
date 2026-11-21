<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Aws\Kms\KmsClient;
use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\Aws\AwsKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\Azure\AzureKeyVaultKey;
use Clavia\Adapter\Secondary\Signing\Remote\Azure\EntraApplication;
use Clavia\Adapter\Secondary\Signing\Remote\Azure\ManagedIdentity;
use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GcpKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GoogleCredentials;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Bootstrap\Container\SigningHttpClientFactory;
use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Error;
use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\FetchAuthTokenInterface;
use InvalidArgumentException;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use ReflectionClass;

/**
 * Builds the {@see RemoteSigningKey} a reference names, for the configured backend — the
 * active key and each retired one alike.
 *
 * Everything that can be checked without calling the provider is checked here, at boot:
 * the reference's shape, the SDK the backend needs, a custom class's contract. Nothing
 * calls the provider: a server whose provider is briefly unreachable still starts.
 */
final class RemoteSigningKeys
{
    /** @var array<string, AccessTokens> One credential per token scope, shared by its keys. */
    private array $tokens = [];

    public function __construct(
        private readonly ContainerInterface $container,
        private readonly Settings $settings,
    ) {
    }

    /**
     * @throws InvalidSettings
     */
    public function key(string $reference): RemoteSigningKey
    {
        try {
            return match ($this->settings->signingBackend) {
                SigningBackend::AWS_KMS => $this->aws($reference),
                SigningBackend::GCP_KMS => $this->gcp($reference),
                SigningBackend::AZURE_KEY_VAULT => $this->azure($reference),
                default => $this->custom($this->settings->signingBackend, $reference),
            };
        } catch (InvalidKeyReference $invalid) {
            throw new InvalidSettings($invalid->getMessage(), previous: $invalid);
        }
    }

    private function aws(string $reference): AwsKmsKey
    {
        self::requirePackage(KmsClient::class, SigningBackend::AWS_KMS, 'aws/aws-sdk-php');
        // Before the client: a reference that cannot be used is the error to report.
        $reference = AwsKmsKey::checked($reference);

        $configuration = [
            'version' => '2014-11-01',
            'http' => [
                'connect_timeout' => SigningHttpClientFactory::CONNECT_TIMEOUT,
                'timeout' => SigningHttpClientFactory::TIMEOUT,
            ],
        ];
        // Unset, the SDK resolves the region itself (AWS_REGION, the shared configuration).
        $region = $this->settings->awsRegion ?? AwsKmsKey::regionOf($reference);
        if ($region !== null) {
            $configuration['region'] = $region;
        }
        if ($this->settings->awsKmsEndpointUrl !== null) {
            $configuration['endpoint'] = $this->settings->awsKmsEndpointUrl;
        }

        try {
            $client = new KmsClient($configuration);
        } catch (InvalidArgumentException $unusable) {
            // The SDK checks its configuration when it is built: no region, a bad endpoint.
            throw new InvalidSettings(sprintf(
                'The AWS KMS client cannot be built (%s). A key named by its id needs CLAVIA_AWS_REGION, or '
                . 'AWS_REGION in the environment.',
                $unusable->getMessage(),
            ), previous: $unusable);
        }

        return new AwsKmsKey($client, $reference);
    }

    private function gcp(string $reference): GcpKmsKey
    {
        self::requirePackage(ApplicationDefaultCredentials::class, SigningBackend::GCP_KMS, 'google/auth');

        $tokens = $this->tokens[GoogleCredentials::SCOPE] ??= new GoogleCredentials(
            static function (): FetchAuthTokenInterface {
                /** @var FetchAuthTokenInterface */
                return ApplicationDefaultCredentials::getCredentials(GoogleCredentials::SCOPE);
            },
            $this->clock(),
        );

        return new GcpKmsKey($this->api('Google Cloud KMS'), $tokens, $reference);
    }

    private function azure(string $reference): AzureKeyVaultKey
    {
        $scope = AzureKeyVaultKey::scopeFor($reference);

        return new AzureKeyVaultKey(
            $this->api('Azure Key Vault'),
            $this->tokens[$scope] ??= $this->azureCredential($scope),
            $reference,
        );
    }

    /**
     * An application when the settings name one, the host's managed identity otherwise.
     */
    private function azureCredential(string $scope): AccessTokens
    {
        $tenant = $this->settings->azureTenantId;
        $client = $this->settings->azureClientId;
        $api = $this->api('Microsoft Entra ID');

        if ($tenant !== null && $client !== null && $this->settings->azureClientSecret !== null) {
            return EntraApplication::withSecret(
                $api,
                $this->clock(),
                $scope,
                $tenant,
                $client,
                $this->settings->azureClientSecret,
            );
        }
        if ($tenant !== null && $client !== null && $this->settings->azureFederatedTokenFile !== null) {
            return EntraApplication::withFederatedToken(
                $api,
                $this->clock(),
                $scope,
                $tenant,
                $client,
                $this->settings->azureFederatedTokenFile,
            );
        }

        // Set by the platform (App Service, Functions, Container Apps), not by the operator.
        $endpoint = getenv('IDENTITY_ENDPOINT');
        $header = getenv('IDENTITY_HEADER');

        return new ManagedIdentity(
            $this->api('The Azure managed identity endpoint'),
            $this->clock(),
            $scope,
            $client,
            $endpoint === false || $endpoint === '' ? null : $endpoint,
            $header === false || $header === '' ? null : $header,
        );
    }

    /**
     * A class of the operator's own: it implements {@see RemoteSigningKey}, and is built
     * from the key reference alone.
     *
     * @throws InvalidSettings
     */
    private function custom(string $class, string $reference): RemoteSigningKey
    {
        if (! class_exists($class) || ! is_subclass_of($class, RemoteSigningKey::class)) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_SIGNING_BACKEND='%s' is neither a built-in backend (%s) nor a class implementing %s.",
                $class,
                implode(', ', SigningBackend::BUILT_IN),
                RemoteSigningKey::class,
            ));
        }

        $type = new ReflectionClass($class);
        if (! $type->isInstantiable()) {
            throw new InvalidSettings(sprintf('The signing backend %s cannot be instantiated.', $class));
        }

        try {
            return $type->newInstance($reference);
        } catch (Error $error) {
            throw new InvalidSettings(sprintf(
                'The signing backend %s is not constructed from a key reference alone: %s',
                $class,
                $error->getMessage(),
            ), previous: $error);
        }
    }

    /**
     * @param non-empty-string $service
     */
    private function api(string $service): JsonApi
    {
        /** @var ClientInterface $http */
        $http = $this->container->get(SigningHttpClientFactory::SERVICE);
        /** @var RequestFactoryInterface $requests */
        $requests = $this->container->get(RequestFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $this->container->get(StreamFactoryInterface::class);

        return new JsonApi($http, $requests, $streams, $service);
    }

    private function clock(): Clock
    {
        /** @var Clock */
        return $this->container->get(Clock::class);
    }

    /**
     * Cloud SDKs are Composer suggestions, so a deployment installs the one it uses.
     *
     * @throws InvalidSettings
     */
    private static function requirePackage(string $class, string $backend, string $package): void
    {
        if (! class_exists($class)) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_SIGNING_BACKEND='%s' needs %s: composer require %s",
                $backend,
                $package,
                $package,
            ));
        }
    }
}
