<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class GrantClientAccessFactory
{
    public function __invoke(ContainerInterface $container): GrantClientAccess
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var ClientGrantRepository $clientGrants */
        $clientGrants = $container->get(ClientGrantRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new GrantClientAccess($clients, $resourceServers, $clientGrants, $clock, $events);
    }
}
