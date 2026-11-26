<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\MetricsMiddleware;
use Clavia\Application\Port\Metrics;
use Psr\Container\ContainerInterface;

final class MetricsMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): MetricsMiddleware
    {
        /** @var Metrics $metrics */
        $metrics = $container->get(Metrics::class);

        return new MetricsMiddleware($metrics);
    }
}
