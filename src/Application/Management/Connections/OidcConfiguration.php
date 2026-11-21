<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Port\DiscoveryFailed;
use Clavia\Application\Port\OidcDiscovery;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Turn what an operator typed into an OIDC connection's settings: discover the issuer now,
 * at the keyboard, and encrypt the client secret for the connection it belongs to.
 */
final readonly class OidcConfiguration
{
    public function __construct(
        private OidcDiscovery $discovery,
        private SecretCipher $cipher,
    ) {
    }

    /**
     * @param string|null $encryptedClientSecret The secret already stored, kept when no new one is given.
     *
     * @throws InvalidValue When discovery fails, a setting is missing or malformed, or the scope
     *                      lacks `openid`.
     */
    public function settings(
        ConnectionName $connection,
        string $issuer,
        string $clientId,
        #[\SensitiveParameter] ?string $clientSecret,
        ?string $encryptedClientSecret,
        ?string $scope,
    ): OidcSettings {
        $noSecret = ($clientSecret === null || $clientSecret === '') && $encryptedClientSecret === null;
        if ($issuer === '' || $clientId === '' || $noSecret) {
            throw new InvalidValue('An OIDC connection needs oidc_issuer, oidc_client_id and oidc_client_secret.');
        }

        try {
            $discovered = $this->discovery->discover($issuer);
        } catch (DiscoveryFailed $failure) {
            throw new InvalidValue($failure->getMessage(), 0, $failure);
        }

        $encrypted = $clientSecret === null || $clientSecret === ''
            ? (string) $encryptedClientSecret
            : $this->cipher->encrypt($clientSecret, OidcSettings::secretContext($connection));

        return OidcSettings::of(
            $issuer,
            $clientId,
            $encrypted,
            ScopeSet::fromString($scope ?? OidcSettings::DEFAULT_SCOPE),
            $discovered->authorizationEndpoint,
            $discovered->tokenEndpoint,
            $discovered->jwksUri,
        );
    }
}
