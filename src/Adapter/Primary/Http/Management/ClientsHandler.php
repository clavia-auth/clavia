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
use Fig\Http\Message\RequestMethodInterface;
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
            RequestMethodInterface::METHOD_GET => $this->responder->json(ManagementViews::page(
                $this->read->page(Paging::fromRequest($management)),
                ManagementViews::client(...),
            )),
            RequestMethodInterface::METHOD_POST => $this->register($management->body),
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
            $body->strings('connections'),
            $body->string('backchannel_logout_uri'),
            $body->bool('backchannel_logout_session_required') ?? false,
            $body->bool('require_pkce') ?? true,
            $body->string('mfa_policy') ?? 'optional',
            $body->bool('require_pushed_authorization_requests') ?? false,
            $body->bool('dpop_bound_access_tokens') ?? false,
        ));

        return $this->responder->created(
            // An operator's client: it did not register itself.
            ManagementViews::clientWithSecret($registered, null),
            '/api/v1/clients/' . rawurlencode($registered->client->id->value),
        );
    }
}
