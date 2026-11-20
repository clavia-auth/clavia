<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Roles\ReadEffectivePermissions;
use Clavia\Domain\Identity\UserId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/users/{user_id}/permissions` (`listUserPermissions`): everything an account
 * holds through its roles, and which roles grant each.
 */
final readonly class UserPermissionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadEffectivePermissions $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $user = UserId::fromString(ManagementRequest::of($request)->path('user_id'));

        return $this->responder->jsonList(array_map(ManagementViews::effectivePermission(...), ($this->read)($user)));
    }
}
