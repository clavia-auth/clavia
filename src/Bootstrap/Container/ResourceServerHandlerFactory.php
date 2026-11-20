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
use Clavia\Adapter\Primary\Http\Management\ResourceServerHandler;
use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Psr\Container\ContainerInterface;

final class ResourceServerHandlerFactory
{
    public function __invoke(ContainerInterface $container): ResourceServerHandler
    {
        /** @var ReadResourceServers $read */
        $read = $container->get(ReadResourceServers::class);
        /** @var UpdateResourceServer $update */
        $update = $container->get(UpdateResourceServer::class);
        /** @var DeleteResourceServer $delete */
        $delete = $container->get(DeleteResourceServer::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ResourceServerHandler($read, $update, $delete, $responder);
    }
}
