<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\ReadRoleHolders;
use Clavia\Application\Management\Roles\RoleAssignments;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Who holds a role: `GET /api/v1/roles/{role_id}/users` (`listRoleUsers`), `POST` to
 * give it to some accounts (`assignRole`), and `DELETE …/users/{user_id}` to take it
 * from one (`unassignRole`).
 */
final readonly class RoleUsersHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadRoleHolders $holders,
        private RoleAssignments $assignments,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $role = RoleId::fromString($management->path('role_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::page(
                    ($this->holders)($role, Paging::fromRequest($management)),
                    ManagementViews::user(...),
                ));
            case 'POST':
                $this->assignments->give($role, RoleFields::userIds($management->body));

                return $this->responder->noContent();
            case 'DELETE':
                $this->assignments->take($role, UserId::fromString($management->path('user_id')));

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
