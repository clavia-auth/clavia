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
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/clients` and `GET /api/v1/clients/{client_id}`: the queries, side by side, and the
 * description every client answer carries — the client with its registration, when it has one.
 */
final readonly class ReadClients
{
    public function __construct(
        private ClientRepository $clients,
        private ClientRegistrationRepository $registrations,
    ) {
    }

    /**
     * A page of clients, their registrations read in one query.
     *
     * @return Page<DescribedClient>
     */
    public function page(PageRequest $request): Page
    {
        $page = $this->clients->page($request);
        $registrations = [];
        $ids = array_map(static fn (Client $client): ClientId => $client->id, $page->items);
        foreach ($this->registrations->ofClients($ids) as $registration) {
            $registrations[$registration->clientId->value] = $registration;
        }

        return $page->map(
            static fn (Client $client): DescribedClient => new DescribedClient(
                $client,
                $registrations[$client->id->value] ?? null,
            ),
        );
    }

    /**
     * @throws NotFound
     */
    public function one(ClientId $id): DescribedClient
    {
        return $this->describe($this->clients->find($id) ?? throw NotFound::of('client'));
    }

    public function describe(Client $client): DescribedClient
    {
        return new DescribedClient($client, $this->registrations->find($client->id));
    }

    /** The registration of a client, when it registered itself. */
    public function registrationOf(Client $client): ?ClientRegistration
    {
        return $this->registrations->find($client->id);
    }
}
