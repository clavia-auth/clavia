<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote\Azure;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;
use Uri\Rfc3986\Uri;

/**
 * A key version in Azure Key Vault or a Managed HSM (`CLAVIA_SIGNING_BACKEND=azure-key-vault`),
 * through its REST API — there is no Key Vault SDK for PHP — with `sign` and `get`, what
 * the **Key Vault Crypto User** role allows.
 *
 * Name the versioned key, `https://<vault>.vault.azure.net/keys/<name>/<version>` (or
 * `…managedhsm.azure.net…`): an unversioned URL follows the key's current version, which
 * changes on rotation. Key Vault names algorithms as JOSE does, and signs a digest.
 */
final readonly class AzureKeyVaultKey implements RemoteSigningKey
{
    public const string API_VERSION = '7.4';

    /** The public clouds' key services, by host suffix, and the scope a token for each needs. */
    private const array SERVICES = [
        '.vault.azure.net' => 'https://vault.azure.net/.default',
        '.managedhsm.azure.net' => 'https://managedhsm.azure.net/.default',
    ];

    private const string SERVICE = 'Azure Key Vault';

    /** @var non-empty-string */
    private string $reference;

    /**
     * @throws InvalidKeyReference When `$reference` is not a versioned key URL of a public-cloud vault.
     */
    public function __construct(
        private JsonApi $api,
        private AccessTokens $tokens,
        string $reference,
    ) {
        self::scopeFor($reference);
        assert($reference !== '');

        $this->reference = $reference;
    }

    /**
     * The token scope the vault `$reference` lives in requires.
     *
     * @throws InvalidKeyReference When `$reference` is not a versioned key URL of a public-cloud vault.
     */
    public static function scopeFor(string $reference): string
    {
        $uri = Uri::parse($reference);
        $host = $uri?->getHost() ?? '';
        $versioned = $uri !== null
            && $uri->getScheme() === 'https'
            && $uri->getUserInfo() === null
            && $uri->getPort() === null
            && $uri->getQuery() === null
            && $uri->getFragment() === null
            && preg_match('/^\/keys\/[0-9A-Za-z-]{1,127}\/[0-9a-f]{32}$/D', $uri->getPath()) === 1;

        foreach (self::SERVICES as $suffix => $scope) {
            if ($versioned && str_ends_with($host, $suffix) && strlen($host) > strlen($suffix)) {
                return $scope;
            }
        }

        throw new InvalidKeyReference(sprintf(
            "An Azure Key Vault signing key is named by its versioned URL, 'https://<vault>.vault.azure.net/keys/"
            . "<name>/<version>' (or a Managed HSM's), not %s.",
            var_export($reference, true),
        ));
    }

    #[\Override]
    public function reference(): string
    {
        return $this->reference;
    }

    #[\Override]
    public function sign(string $digest, SigningAlgorithm $algorithm): string
    {
        $answer = $this->api->postJson(
            $this->reference . '/sign?api-version=' . self::API_VERSION,
            ['alg' => $algorithm->value, 'value' => Base64Url::encode($digest)],
            $this->authorization(),
        );

        if (($answer['kid'] ?? null) !== $this->reference) {
            throw new SigningFailed(sprintf('%s signed with a key other than %s.', self::SERVICE, $this->reference));
        }

        $signature = self::decoded($answer['value'] ?? null);
        if ($signature === '') {
            throw new SigningFailed(sprintf('%s returned no signature.', self::SERVICE));
        }

        return $signature;
    }

    #[\Override]
    public function publicKey(SigningAlgorithm $algorithm): PublicJwk
    {
        $answer = $this->api->get($this->reference . '?api-version=' . self::API_VERSION, $this->authorization());

        /** @var mixed $key */
        $key = $answer['key'] ?? null;
        /** @var mixed $attributes */
        $attributes = $answer['attributes'] ?? [];
        /** @var mixed $operations */
        $operations = is_array($key) ? ($key['key_ops'] ?? []) : null;
        if (
            ! is_array($key)
            || ($key['kid'] ?? null) !== $this->reference
            || ! in_array($key['kty'] ?? null, ['RSA', 'RSA-HSM'], true)
            || ! is_array($operations)
            || ! in_array('sign', $operations, true)
            || (is_array($attributes) && ($attributes['enabled'] ?? true) === false)
        ) {
            throw new SigningFailed(sprintf(
                '%s key %s is not an enabled RSA key that may sign.',
                self::SERVICE,
                $this->reference,
            ));
        }

        try {
            return PublicJwk::rsa(self::decoded($key['n'] ?? null), self::decoded($key['e'] ?? null), $algorithm);
        } catch (InvalidValue $unusable) {
            throw new SigningFailed(sprintf('%s returned an unusable public key.', self::SERVICE), previous: $unusable);
        }
    }

    /**
     * @return array{Authorization: string}
     */
    private function authorization(): array
    {
        return ['Authorization' => 'Bearer ' . $this->tokens->token()];
    }

    /**
     * @throws SigningFailed When `$value` is not base64url.
     */
    private static function decoded(mixed $value): string
    {
        try {
            return is_string($value) ? Base64Url::decode($value) : '';
        } catch (InvalidValue $malformed) {
            throw new SigningFailed(sprintf('%s returned a malformed value.', self::SERVICE), previous: $malformed);
        }
    }
}
