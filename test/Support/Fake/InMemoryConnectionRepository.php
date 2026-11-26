<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Shared\AlreadyExists;
use DateTimeImmutable;

/**
 * Connections in memory, starting — like a migrated database — with the built-in ones:
 * the default pool, Google and GitHub, all switched on, the pool alone open to every
 * application.
 *
 * Given the clients, a deleted connection stops being enabled for them, as the cascade
 * on `client_connections` does.
 */
final class InMemoryConnectionRepository implements ConnectionRepository
{
    /** @var array<string, Connection> By name. */
    private array $connections = [];

    public function __construct(private readonly ?InMemoryClientRepository $clients = null)
    {
        $seeded = new DateTimeImmutable('2026-01-01T00:00:00Z');
        foreach (
            [
                ['password', 'Username-Password', ConnectionStrategy::Database, true],
                ['email', 'Email', ConnectionStrategy::Passwordless, false],
                ['google', 'Google', ConnectionStrategy::Social, false],
                ['github', 'GitHub', ConnectionStrategy::Social, false],
            ] as [$name, $displayName, $strategy, $isDomainConnection]
        ) {
            $this->connections[$name] = Connection::reconstitute(
                ConnectionName::fromString($name),
                $displayName,
                $strategy,
                true,
                $isDomainConnection,
                null,
                $seeded,
            );
        }
    }

    #[\Override]
    public function find(ConnectionName $name): ?Connection
    {
        return $this->connections[$name->value] ?? null;
    }

    #[\Override]
    public function all(): array
    {
        $connections = $this->connections;
        ksort($connections, SORT_STRING);

        return array_values($connections);
    }

    #[\Override]
    public function add(Connection $connection): void
    {
        if (isset($this->connections[$connection->name->value])) {
            throw new AlreadyExists('A connection with this name already exists.');
        }

        $this->connections[$connection->name->value] = $connection;
    }

    #[\Override]
    public function save(Connection $connection): void
    {
        $this->connections[$connection->name->value] = $connection;
    }

    #[\Override]
    public function delete(ConnectionName $name): void
    {
        unset($this->connections[$name->value]);
        $clients = $this->clients;
        if ($clients === null) {
            return;
        }

        foreach ($clients->all() as $client) {
            if ($client->enables($name)) {
                $clients->save($client->withConnections(array_values(array_filter(
                    $client->connections,
                    static fn (ConnectionName $enabled): bool => ! $enabled->equals($name),
                ))));
            }
        }
    }
}
