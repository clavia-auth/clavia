<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ClientConnectionsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\Clients\ClientConnections;
use Psr\Container\ContainerInterface;

final class ClientConnectionsHandlerFactory
{
    public function __invoke(ContainerInterface $container): ClientConnectionsHandler
    {
        /** @var ClientConnections $connections */
        $connections = $container->get(ClientConnections::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ClientConnectionsHandler($connections, $responder);
    }
}
