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
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class RedisConnectionFactory
{
    public function __invoke(ContainerInterface $container): RedisConnection
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        // Lazy, like the database: nothing connects until a store is used.
        return new RedisConnection($settings->redisUrl);
    }
}
