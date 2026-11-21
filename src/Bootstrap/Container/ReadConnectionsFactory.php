<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Domain\Connection\ConnectionRepository;
use Psr\Container\ContainerInterface;

final class ReadConnectionsFactory
{
    public function __invoke(ContainerInterface $container): ReadConnections
    {
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);

        return new ReadConnections($connections, $access);
    }
}
