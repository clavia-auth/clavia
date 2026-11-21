<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\NewClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\RegisterClient;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/clients`: `GET` lists clients (`listClients`), `POST` registers one
 * (`createClient`) and answers with its secret, the only time it is shown.
 */
final readonly class ClientsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadClients $read,
        private RegisterClient $register,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);

        return match ($request->getMethod()) {
            'GET' => $this->responder->json(ManagementViews::page(
                $this->read->page(Paging::fromRequest($management)),
                ManagementViews::client(...),
            )),
            'POST' => $this->register($management->body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function register(JsonObject $body): ResponseInterface
    {
        $registered = ($this->register)(new NewClient(
            $body->string('name') ?? '',
            $body->string('client_type') ?? 'public',
            $body->string('token_endpoint_auth_method'),
            $body->strings('redirect_uris') ?? [],
            $body->strings('grant_types') ?? [],
            $body->strings('response_types') ?? [],
            $body->strings('post_logout_redirect_uris') ?? [],
            $body->bool('is_first_party') ?? true,
        ));

        return $this->responder->created(
            ManagementViews::clientWithSecret($registered),
            '/api/v1/clients/' . rawurlencode($registered->client->id->value),
        );
    }
}
