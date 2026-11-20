<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\NewResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\RegisterResourceServer;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/resource-servers`: `GET` lists APIs (`listResourceServers`), `POST`
 * registers one (`createResourceServer`).
 */
final readonly class ResourceServersHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadResourceServers $read,
        private RegisterResourceServer $register,
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
                ManagementViews::resourceServer(...),
            )),
            'POST' => $this->register($management->body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function register(JsonObject $body): ResponseInterface
    {
        $api = ($this->register)(new NewResourceServer(
            $body->string('identifier') ?? throw new LogicException("The contract requires 'identifier'."),
            $body->string('name') ?? '',
            ResourceServerFields::permissions($body) ?? [],
        ));

        return $this->responder->created(
            ManagementViews::resourceServer($api),
            '/api/v1/resource-servers/' . $api->id->value,
        );
    }
}
