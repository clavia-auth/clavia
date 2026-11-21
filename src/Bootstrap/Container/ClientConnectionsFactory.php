<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\ClientConnections;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionRepository;
use Psr\Container\ContainerInterface;

final class ClientConnectionsFactory
{
    public function __invoke(ContainerInterface $container): ClientConnections
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new ClientConnections($clients, $connections, $events);
    }
}
