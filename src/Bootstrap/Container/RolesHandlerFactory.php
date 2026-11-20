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
use Clavia\Adapter\Primary\Http\Management\RolesHandler;
use Clavia\Application\Management\Roles\CreateRole;
use Clavia\Application\Management\Roles\ReadRoles;
use Psr\Container\ContainerInterface;

final class RolesHandlerFactory
{
    public function __invoke(ContainerInterface $container): RolesHandler
    {
        /** @var ReadRoles $read */
        $read = $container->get(ReadRoles::class);
        /** @var CreateRole $create */
        $create = $container->get(CreateRole::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new RolesHandler($read, $create, $responder);
    }
}
