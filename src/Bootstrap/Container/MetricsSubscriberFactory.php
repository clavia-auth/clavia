<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Metrics\MetricsSubscriber;
use Clavia\Application\Port\Metrics;
use Psr\Container\ContainerInterface;

final class MetricsSubscriberFactory
{
    public function __invoke(ContainerInterface $container): MetricsSubscriber
    {
        /** @var Metrics $metrics */
        $metrics = $container->get(Metrics::class);

        return new MetricsSubscriber($metrics);
    }
}
