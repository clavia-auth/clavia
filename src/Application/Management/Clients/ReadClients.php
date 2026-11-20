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
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/clients` and `GET /api/v1/clients/{client_id}`: the queries, side by side.
 */
final readonly class ReadClients
{
    public function __construct(private ClientRepository $clients)
    {
    }

    /** @return Page<Client> */
    public function page(PageRequest $request): Page
    {
        return $this->clients->page($request);
    }

    /**
     * @throws NotFound
     */
    public function one(ClientId $id): Client
    {
        return $this->clients->find($id) ?? throw NotFound::of('client');
    }
}
