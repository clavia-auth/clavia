<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Device\PendingDeviceRequests;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class PendingDeviceRequestsFactory
{
    public function __invoke(ContainerInterface $container): PendingDeviceRequests
    {
        /** @var DeviceAuthorizationStore $store */
        $store = $container->get(DeviceAuthorizationStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new PendingDeviceRequests($store, $clients, $clock);
    }
}
