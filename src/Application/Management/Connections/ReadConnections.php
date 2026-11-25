<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /api/v1/connections[/{name}]`: the ways users can sign in, and whether each works.
 */
final readonly class ReadConnections
{
    public function __construct(
        private ConnectionRepository $connections,
        private ConnectionAccess $access,
        private SamlServiceProviderEndpoints $endpoints,
        private ServiceProviderKeys $keys,
    ) {
    }

    /**
     * @return list<DescribedConnection> By name.
     */
    public function all(): array
    {
        return array_map($this->describe(...), $this->connections->all());
    }

    /**
     * @throws NotFound
     */
    public function one(string $name): DescribedConnection
    {
        return $this->describe(self::find($this->connections, $name));
    }

    public function describe(Connection $connection): DescribedConnection
    {
        return new DescribedConnection(
            $connection,
            $this->access->isConfigured($connection),
            $this->access->isUsable($connection),
            $connection->saml === null ? null : new DescribedServiceProvider(
                $this->endpoints->entityId($connection->name),
                $this->endpoints->assertionConsumerService($connection->name),
                $this->endpoints->metadata($connection->name),
                $this->keysWarning(),
            ),
        );
    }

    /**
     * Without keys a SAML connection still works, unsigned and unencrypted: the operator is told.
     *
     * @return non-empty-string|null
     */
    private function keysWarning(): ?string
    {
        try {
            $current = $this->keys->certificates()->current(ServiceProviderKeyUsage::Signing);
        } catch (SigningFailed | DecryptionFailed) {
            return 'The SAML service provider keys cannot be read from their KMS now: the metadata lacks '
                . 'their certificates until they can.';
        }

        return $current !== null ? null : 'This server has no SAML service provider keys yet: requests are not '
            . 'signed and assertions cannot be encrypted to it. Run `clavia saml-keys:generate`.';
    }

    /**
     * The connection of that name; a name no connection could have is as unknown as an
     * unused one.
     *
     * @throws NotFound
     */
    public static function find(ConnectionRepository $connections, string $name): Connection
    {
        try {
            $connection = $connections->find(ConnectionName::fromString($name));
        } catch (InvalidValue) {
            $connection = null;
        }

        return $connection ?? throw NotFound::of('connection');
    }
}
