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
use Clavia\Adapter\Secondary\Signing\Remote\IssuedToken;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Application\Port\SigningFailed;
use Clavia\Configuration\LocalFilePath;
use Clavia\Domain\Shared\Clock;

/**
 * Tokens for a Microsoft Entra application, by the client credentials grant: for a server
 * outside Azure, with a client secret, or on AKS with workload identity, presenting the
 * token Kubernetes projects into the pod.
 *
 * The projected token is read for every request, never kept: Kubernetes replaces it
 * before it expires.
 */
final class EntraApplication implements AccessTokens
{
    public const string AUTHORITY = 'https://login.microsoftonline.com/';

    private const string SERVICE = 'Microsoft Entra ID';

    private const string JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    private ?IssuedToken $current = null;

    private function __construct(
        private readonly JsonApi $api,
        private readonly Clock $clock,
        private readonly string $scope,
        private readonly string $tenantId,
        private readonly string $clientId,
        #[\SensitiveParameter] private readonly ?string $secret,
        private readonly ?string $federatedTokenFile,
    ) {
    }

    public static function withSecret(
        JsonApi $api,
        Clock $clock,
        string $scope,
        string $tenantId,
        string $clientId,
        #[\SensitiveParameter] string $secret,
    ): self {
        return new self($api, $clock, $scope, $tenantId, $clientId, $secret, null);
    }

    public static function withFederatedToken(
        JsonApi $api,
        Clock $clock,
        string $scope,
        string $tenantId,
        string $clientId,
        string $tokenFile,
    ): self {
        return new self($api, $clock, $scope, $tenantId, $clientId, null, $tokenFile);
    }

    #[\Override]
    public function token(): string
    {
        $now = $this->clock->now();
        if ($this->current?->isUsableAt($now) !== true) {
            $answer = $this->api->postForm(
                self::AUTHORITY . rawurlencode($this->tenantId) . '/oauth2/v2.0/token',
                ['grant_type' => 'client_credentials', 'client_id' => $this->clientId, 'scope' => $this->scope]
                    + $this->proof(),
            );
            $this->current = IssuedToken::fromResponse($answer, $now, self::SERVICE);
        }

        return $this->current->token;
    }

    /**
     * @return array<string, string>
     */
    private function proof(): array
    {
        if ($this->secret !== null) {
            return ['client_secret' => $this->secret];
        }

        $assertion = $this->federatedTokenFile === null
            ? false
            : @file_get_contents(self::local($this->federatedTokenFile));
        if ($assertion === false || trim($assertion) === '') {
            throw new SigningFailed(sprintf(
                'The federated token file %s cannot be read.',
                var_export($this->federatedTokenFile, true),
            ));
        }

        return ['client_assertion_type' => self::JWT_BEARER, 'client_assertion' => trim($assertion)];
    }

    /**
     * The federated token file, as a path on this host and nothing else. It is the operator's
     * setting (CLAVIA_AZURE_FEDERATED_TOKEN_FILE, refused at boot when it is not one), and reading
     * the file it names is the point: once it is a local absolute path, it can neither reach the
     * network nor a stream wrapper, nor be part of a URL.
     *
     * @psalm-taint-escape ssrf
     * @psalm-taint-escape file
     * @psalm-taint-escape url_component
     * @psalm-taint-escape url_path
     * @psalm-taint-escape url_scheme
     *
     * @throws SigningFailed
     */
    private static function local(string $path): string
    {
        if (! LocalFilePath::isAbsolute($path)) {
            throw new SigningFailed('The federated token file must be an absolute local path.');
        }

        return $path;
    }
}
