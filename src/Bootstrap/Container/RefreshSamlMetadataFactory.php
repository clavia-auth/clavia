<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Connections\RefreshSamlMetadata;
use Clavia\Application\Management\Connections\SamlConfiguration;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\ConnectionRepository;
use Psr\Container\ContainerInterface;

final class RefreshSamlMetadataFactory
{
    public function __invoke(ContainerInterface $container): RefreshSamlMetadata
    {
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var SamlConfiguration $configuration */
        $configuration = $container->get(SamlConfiguration::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new RefreshSamlMetadata($connections, $configuration, $events);
    }
}
