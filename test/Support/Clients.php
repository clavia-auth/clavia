<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;

/**
 * Ready-made client registrations for unit tests, so a test states only what it is about.
 *
 * A first-party one enables the built-in connections — the default pool, Google and
 * GitHub — as every first-party client did when connections came in; a third-party one
 * lists none, as it must.
 */
final class Clients
{
    public const string REDIRECT_URI = 'https://app.example/cb';

    private function __construct()
    {
    }

    /** @return list<ConnectionName> */
    public static function builtInConnections(string $id): array
    {
        return ClientId::fromString($id)->ownership() === Ownership::ThirdParty
            ? []
            : array_map(
                ConnectionName::fromString(...),
                [ConnectionName::EMAIL, 'github', 'google', ConnectionName::DEFAULT_POOL],
            );
    }

    /**
     * A single-page or native application: no secret, PKCE only.
     *
     * @param list<string>       $redirectUris
     * @param list<GrantType>    $grantTypes
     * @param list<ResponseType> $responseTypes
     */
    public static function public(
        string $id = 'spa',
        array $redirectUris = [self::REDIRECT_URI],
        array $grantTypes = [GrantType::AuthorizationCode],
        array $responseTypes = [ResponseType::Code],
    ): Client {
        return Client::register(
            ClientId::fromString($id),
            'A public client',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            array_map(Url::fromString(...), $redirectUris),
            $grantTypes,
            $responseTypes,
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            [],
            self::builtInConnections($id),
        );
    }

    /**
     * A server-side application holding a secret.
     *
     * @param string $secretHash What the password hasher under test produced for its secret.
     */
    public static function confidential(
        string $id,
        string $secretHash,
        ClientAuthMethod $authMethod = ClientAuthMethod::ClientSecretBasic,
    ): Client {
        return Client::register(
            ClientId::fromString($id),
            'A confidential client',
            ClientType::Confidential,
            $authMethod,
            $secretHash,
            [Url::fromString(self::REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            [],
            self::builtInConnections($id),
        );
    }
}
