<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\Connections\CreateConnection;
use Clavia\Application\Management\Connections\ReadConnections;
use Psr\Container\ContainerInterface;

final class ConnectionsHandlerFactory
{
    public function __invoke(ContainerInterface $container): ConnectionsHandler
    {
        /** @var ReadConnections $read */
        $read = $container->get(ReadConnections::class);
        /** @var CreateConnection $create */
        $create = $container->get(CreateConnection::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ConnectionsHandler($read, $create, $responder);
    }
}
