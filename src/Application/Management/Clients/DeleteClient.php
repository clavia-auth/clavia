<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientDeleted;

/**
 * `DELETE /api/v1/clients/{client_id}`: the client, and every code, token and grant it
 * holds.
 */
final readonly class DeleteClient
{
    public function __construct(
        private ClientRepository $clients,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws Conflict When it is the client the caller's token was issued to: the cascade would
     *                  take that token with it, half-way through the request, and lock out the
     *                  operator who would need it to recover.
     */
    public function __invoke(ClientId $id, ManagementCaller $caller): void
    {
        $client = $this->clients->find($id) ?? throw NotFound::of('client');
        if ($caller->isClient($client->id)) {
            throw new Conflict('A token cannot delete the client it was issued to.');
        }

        $this->clients->delete($client->id);
        $this->events->dispatch(new ClientDeleted($client));
    }
}
