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
use Clavia\Application\OAuth2\Device\DecideDeviceRequest;
use Clavia\Application\OAuth2\Device\PendingDeviceRequests;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class DecideDeviceRequestFactory
{
    public function __invoke(ContainerInterface $container): DecideDeviceRequest
    {
        /** @var PendingDeviceRequests $pending */
        $pending = $container->get(PendingDeviceRequests::class);
        /** @var DeviceAuthorizationStore $store */
        $store = $container->get(DeviceAuthorizationStore::class);
        /** @var ConnectionAccess $connections */
        $connections = $container->get(ConnectionAccess::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var ConsentRepository $consents */
        $consents = $container->get(ConsentRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new DecideDeviceRequest(
            $pending,
            $store,
            $connections,
            $resourceServers,
            $roles,
            $consents,
            $clock,
            $events,
        );
    }
}
