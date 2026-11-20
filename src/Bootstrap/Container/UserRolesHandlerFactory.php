<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\UserRolesHandler;
use Clavia\Application\Management\Roles\RoleAssignments;
use Psr\Container\ContainerInterface;

final class UserRolesHandlerFactory
{
    public function __invoke(ContainerInterface $container): UserRolesHandler
    {
        /** @var RoleAssignments $assignments */
        $assignments = $container->get(RoleAssignments::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new UserRolesHandler($assignments, $responder);
    }
}
