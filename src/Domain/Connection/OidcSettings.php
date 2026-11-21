<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;

/**
 * What an OpenID Connect connection needs to sign somebody in at its provider.
 *
 * The endpoints are what discovery said when the connection was registered or its
 * issuer changed — fetched then, at the operator's keyboard where a wrong URL can be
 * corrected, rather than at every sign-in. The client secret is kept encrypted, bound
 * to the connection's name, and decrypted only where it is sent to the provider.
 */
final readonly class OidcSettings
{
    public const string DEFAULT_SCOPE = 'openid profile email';

    private const int MAX_URL_LENGTH = 2048;

    private const int MAX_CLIENT_ID_LENGTH = 255;

    /**
     * @param non-empty-string $clientId
     * @param non-empty-string $encryptedClientSecret
     */
    private function __construct(
        public Url $issuer,
        public string $clientId,
        public string $encryptedClientSecret,
        public ScopeSet $scope,
        public Url $authorizationEndpoint,
        public Url $tokenEndpoint,
        public Url $jwksUri,
    ) {
    }

    /**
     * @param string $encryptedClientSecret What the secret cipher made of the secret, bound to the
     *                                      connection's name.
     *
     * @throws InvalidValue When a URL is not an absolute https URL of at most 2048 bytes, the client
     *                      id is empty or longer than 255 bytes, or the scope lacks `openid`.
     */
    public static function of(
        string $issuer,
        string $clientId,
        string $encryptedClientSecret,
        ScopeSet $scope,
        string $authorizationEndpoint,
        string $tokenEndpoint,
        string $jwksUri,
    ): self {
        if ($clientId === '' || strlen($clientId) > self::MAX_CLIENT_ID_LENGTH) {
            throw new InvalidValue('An OIDC client id is 1 to 255 bytes.');
        }
        if ($encryptedClientSecret === '') {
            throw new InvalidValue('An OIDC connection has a client secret.');
        }
        if (! $scope->contains(OidcScope::OPENID)) {
            throw new InvalidValue("The scope of an OIDC connection includes 'openid'.");
        }

        return new self(
            self::https($issuer),
            $clientId,
            $encryptedClientSecret,
            $scope,
            self::https($authorizationEndpoint),
            self::https($tokenEndpoint),
            self::https($jwksUri),
        );
    }

    /**
     * What the client secret's ciphertext is bound to: the connection it belongs to. A secret
     * moved onto another connection's row does not decrypt.
     */
    public static function secretContext(ConnectionName $connection): string
    {
        return 'connection:' . $connection->value;
    }

    /**
     * @throws InvalidValue
     */
    private static function https(string $value): Url
    {
        $url = Url::fromString($value);
        if ($url->scheme() !== 'https' || strlen($value) > self::MAX_URL_LENGTH) {
            throw new InvalidValue('The URLs of an OIDC connection are https, at most 2048 bytes.');
        }

        return $url;
    }
}
