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
use Clavia\Adapter\Secondary\Redis\RedisMetrics;
use Clavia\Application\Metrics\NoMetrics;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Application\Port\Metrics;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The metrics `CLAVIA_METRICS_ENABLED` asks for: kept in Redis, a request's samples written in one
 * round trip once its response is out (the deferred tasks the entry point runs, which the store asks
 * for whenever it holds samples again); or none at all.
 */
final class MetricsFactory
{
    public function __invoke(ContainerInterface $container): Metrics
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        if (! $settings->metricsEnabled) {
            return new NoMetrics();
        }
        /** @var RedisConnection $redis */
        $redis = $container->get(RedisConnection::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);
        /** @var DeferredTasks $deferred */
        $deferred = $container->get(DeferredTasks::class);

        return new RedisMetrics($redis, $logger, $deferred->defer(...));
    }
}
