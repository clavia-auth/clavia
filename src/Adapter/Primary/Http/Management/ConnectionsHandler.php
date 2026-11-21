<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Connections\CreateConnection;
use Clavia\Application\Management\Connections\NewConnection;
use Clavia\Application\Management\Connections\ReadConnections;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/connections`: `GET` lists them (`listConnections`) — few by nature, so an
 * array, not a page — and `POST` creates a pool or registers a provider (`createConnection`).
 */
final readonly class ConnectionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadConnections $read,
        private CreateConnection $create,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = ManagementRequest::of($request)->body;

        return match ($request->getMethod()) {
            'GET' => $this->responder->jsonList(array_map(ManagementViews::connection(...), $this->read->all())),
            'POST' => $this->create($body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function create(JsonObject $body): ResponseInterface
    {
        $connection = ($this->create)(new NewConnection(
            $body->string('name') ?? throw new LogicException("The contract requires 'name'."),
            $body->string('display_name') ?? throw new LogicException("The contract requires 'display_name'."),
            $body->string('strategy') ?? throw new LogicException("The contract requires 'strategy'."),
            $body->bool('is_enabled') ?? true,
            $body->bool('is_domain_connection') ?? false,
            $body->string('oidc_issuer'),
            $body->string('oidc_client_id'),
            $body->string('oidc_client_secret'),
            $body->string('oidc_scope'),
        ));

        return $this->responder->created(
            ManagementViews::connection($this->read->describe($connection)),
            '/api/v1/connections/' . $connection->name->value,
        );
    }
}
