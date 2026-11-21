<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\ClientConnections;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `PUT /api/v1/clients/{client_id}/connections` (`setClientConnections`): the connections
 * an application's users may sign in through, replaced as a whole; answers the new list.
 */
final readonly class ClientConnectionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ClientConnections $connections,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $client = ($this->connections)(
            ClientId::fromString($management->path('client_id')),
            $management->body->strings('connections')
                ?? throw new LogicException("The contract requires 'connections'."),
        );

        return $this->responder->jsonList(array_map(
            static fn (ConnectionName $connection): string => $connection->value,
            $client->connections,
        ));
    }
}
