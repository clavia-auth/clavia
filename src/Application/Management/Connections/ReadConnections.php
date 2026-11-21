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
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `GET /api/v1/connections[/{name}]`: the ways users can sign in, and whether each works.
 */
final readonly class ReadConnections
{
    public function __construct(
        private ConnectionRepository $connections,
        private ConnectionAccess $access,
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
        );
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
