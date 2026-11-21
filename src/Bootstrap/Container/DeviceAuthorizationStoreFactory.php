<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisDeviceAuthorizationStore;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class DeviceAuthorizationStoreFactory
{
    public function __invoke(ContainerInterface $container): RedisDeviceAuthorizationStore
    {
        /** @var RedisConnection $redis */
        $redis = $container->get(RedisConnection::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new RedisDeviceAuthorizationStore($redis, $clock);
    }
}
