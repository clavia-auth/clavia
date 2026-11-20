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
use Clavia\Adapter\Primary\Http\Management\ResourceServersHandler;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\RegisterResourceServer;
use Psr\Container\ContainerInterface;

final class ResourceServersHandlerFactory
{
    public function __invoke(ContainerInterface $container): ResourceServersHandler
    {
        /** @var ReadResourceServers $read */
        $read = $container->get(ReadResourceServers::class);
        /** @var RegisterResourceServer $register */
        $register = $container->get(RegisterResourceServer::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ResourceServersHandler($read, $register, $responder);
    }
}
