<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\CreateRole;
use Clavia\Application\Management\Roles\NewRole;
use Clavia\Application\Management\Roles\ReadRoles;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/roles`: `GET` lists roles (`listRoles`), `POST` defines one (`createRole`).
 */
final readonly class RolesHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadRoles $read,
        private CreateRole $create,
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
                ManagementViews::role(...),
            )),
            'POST' => $this->create($management->body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function create(JsonObject $body): ResponseInterface
    {
        $role = ($this->create)(new NewRole(
            $body->string('name') ?? throw new LogicException("The contract requires 'name'."),
            $body->string('description') ?? '',
            RoleFields::permissions($body) ?? [],
        ));

        return $this->responder->created(
            ManagementViews::roleWithPermissions($this->read->describe($role)),
            '/api/v1/roles/' . $role->id->value,
        );
    }
}
