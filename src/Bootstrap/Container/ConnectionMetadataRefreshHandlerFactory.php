<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ConnectionMetadataRefreshHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\Connections\RefreshSamlMetadata;
use Psr\Container\ContainerInterface;

final class ConnectionMetadataRefreshHandlerFactory
{
    public function __invoke(ContainerInterface $container): ConnectionMetadataRefreshHandler
    {
        /** @var RefreshSamlMetadata $refresh */
        $refresh = $container->get(RefreshSamlMetadata::class);
        /** @var ReadConnections $read */
        $read = $container->get(ReadConnections::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ConnectionMetadataRefreshHandler($refresh, $read, $responder);
    }
}
