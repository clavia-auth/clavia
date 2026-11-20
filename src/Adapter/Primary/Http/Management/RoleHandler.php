<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\DeleteRole;
use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\RoleChanges;
use Clavia\Application\Management\Roles\UpdateRole;
use Clavia\Domain\Rbac\RoleId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/roles/{role_id}`: `GET` (`getRole`), `PATCH` (`updateRole`), `DELETE`
 * (`deleteRole`).
 */
final readonly class RoleHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadRoles $read,
        private UpdateRole $update,
        private DeleteRole $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = RoleId::fromString($management->path('role_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::roleWithPermissions($this->read->one($id)));
            case 'PATCH':
                $role = ($this->update)($id, new RoleChanges(
                    $management->body->string('name'),
                    $management->body->string('description'),
                    RoleFields::permissions($management->body),
                ));

                return $this->responder->json(ManagementViews::roleWithPermissions($this->read->describe($role)));
            case 'DELETE':
                ($this->delete)($id);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
