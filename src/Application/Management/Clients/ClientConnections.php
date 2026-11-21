<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PUT /api/v1/clients/{client_id}/connections`: the connections an application's users
 * may sign in through, replaced as a whole — and the names behind every list given.
 *
 * Takes effect at the next sign-in, and at the next authorization request: a session
 * established through a connection the application stops enabling no longer counts for
 * it. A third-party application cannot be given a list (422): it signs people in through
 * the domain connections.
 */
final readonly class ClientConnections
{
    public function __construct(
        private ClientRepository $clients,
        private ConnectionRepository $connections,
    ) {
    }

    /**
     * @param list<string> $names
     *
     * @throws NotFound     When the client or one of the connections does not exist.
     * @throws InvalidValue When the client is third-party.
     */
    public function __invoke(ClientId $id, array $names): Client
    {
        $client = $this->clients->find($id) ?? throw NotFound::of('client');

        $updated = $client->withConnections($this->existing($names));
        $this->clients->save($updated);

        return $updated;
    }

    /**
     * The connections those names are, each existing.
     *
     * @param list<string> $names
     *
     * @return list<ConnectionName>
     *
     * @throws NotFound
     */
    public function existing(array $names): array
    {
        $known = [];
        foreach ($this->connections->all() as $connection) {
            $known[$connection->name->value] = $connection->name;
        }

        return array_map(
            static fn (string $name): ConnectionName => $known[$name] ?? throw NotFound::of('connection'),
            array_values(array_unique($names)),
        );
    }

    /**
     * What a new first-party application enables when it names nothing: every connection
     * there is.
     *
     * @return list<ConnectionName>
     */
    public function every(): array
    {
        return array_map(
            static fn (Connection $connection): ConnectionName => $connection->name,
            $this->connections->all(),
        );
    }
}
