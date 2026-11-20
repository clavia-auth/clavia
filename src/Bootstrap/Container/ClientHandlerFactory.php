<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ClientHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\UpdateClient;
use Psr\Container\ContainerInterface;

final class ClientHandlerFactory
{
    public function __invoke(ContainerInterface $container): ClientHandler
    {
        /** @var ReadClients $read */
        $read = $container->get(ReadClients::class);
        /** @var UpdateClient $update */
        $update = $container->get(UpdateClient::class);
        /** @var DeleteClient $delete */
        $delete = $container->get(DeleteClient::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ClientHandler($read, $update, $delete, $responder);
    }
}
