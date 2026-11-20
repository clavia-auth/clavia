<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\RoleAssignments;
use Clavia\Domain\Identity\UserId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/users/{user_id}/roles`: `GET` the roles an account holds (`listUserRoles`),
 * `PUT` exactly which it holds (`setUserRoles`).
 */
final readonly class UserRolesHandler implements RequestHandlerInterface
{
    public function __construct(
        private RoleAssignments $assignments,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $user = UserId::fromString($management->path('user_id'));

        $roles = match ($request->getMethod()) {
            'GET' => $this->assignments->rolesOf($user),
            'PUT' => $this->assignments->replaceRolesOf($user, RoleFields::roleIds($management->body)),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };

        return $this->responder->jsonList(array_map(ManagementViews::role(...), $roles));
    }
}
