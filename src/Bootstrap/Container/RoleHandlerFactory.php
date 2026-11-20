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
use Clavia\Adapter\Primary\Http\Management\RoleHandler;
use Clavia\Application\Management\Roles\DeleteRole;
use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\UpdateRole;
use Psr\Container\ContainerInterface;

final class RoleHandlerFactory
{
    public function __invoke(ContainerInterface $container): RoleHandler
    {
        /** @var ReadRoles $read */
        $read = $container->get(ReadRoles::class);
        /** @var UpdateRole $update */
        $update = $container->get(UpdateRole::class);
        /** @var DeleteRole $delete */
        $delete = $container->get(DeleteRole::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new RoleHandler($read, $update, $delete, $responder);
    }
}
