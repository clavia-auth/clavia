<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\ClientChanges;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Domain\Client\ClientId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/clients/{client_id}`: `GET` (`getClient`), `PATCH` (`updateClient`),
 * `DELETE` (`deleteClient`).
 */
final readonly class ClientHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadClients $read,
        private UpdateClient $update,
        private DeleteClient $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = ClientId::fromString($management->path('client_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::client($this->read->one($id)));
            case 'PATCH':
                $body = $management->body;

                return $this->responder->json(ManagementViews::client(($this->update)($id, new ClientChanges(
                    $body->string('name'),
                    $body->string('token_endpoint_auth_method'),
                    $body->strings('redirect_uris'),
                    $body->strings('grant_types'),
                    $body->strings('response_types'),
                ))));
            case 'DELETE':
                ($this->delete)($id, $management->caller);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
