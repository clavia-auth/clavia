<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Domain\Connection\ConnectionName;

/**
 * Where this server is, as one connection's service provider (docs/design/saml-connections.md §2,
 * "Entity ID"): `https://auth.{domain}/auth/saml/{connection}`, one per connection, since two
 * connections can be two tenants of one identity provider, which refuses two applications with one
 * entity ID. The assertion consumer service and the metadata hang below it.
 */
final readonly class SamlServiceProviderEndpoints
{
    /** @param non-empty-string $issuer This server's issuer: the sign-in origin. */
    public function __construct(private string $issuer)
    {
    }

    /** @return non-empty-string */
    public function entityId(ConnectionName $connection): string
    {
        return rtrim($this->issuer, '/') . '/auth/saml/' . $connection->value;
    }

    /** @return non-empty-string */
    public function assertionConsumerService(ConnectionName $connection): string
    {
        return $this->entityId($connection) . '/acs';
    }

    /** @return non-empty-string */
    public function metadata(ConnectionName $connection): string
    {
        return $this->entityId($connection) . '/metadata';
    }
}
