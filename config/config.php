<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Laminas\ConfigAggregator\ArrayProvider;
use Laminas\ConfigAggregator\ConfigAggregator;

// Framework wiring first, Clavia's composition root last so that it has the final say.
// There is no configuration cache: the application's own settings come from the
// environment (see Clavia\Configuration\Settings), not from files merged here.
return new ConfigAggregator([
    Laminas\Diactoros\ConfigProvider::class,
    Laminas\HttpHandlerRunner\ConfigProvider::class,
    Mezzio\ConfigProvider::class,
    Mezzio\Router\ConfigProvider::class,
    Mezzio\Router\FastRouteRouter\ConfigProvider::class,
    Laminas\View\ConfigProvider::class,
    Mezzio\LaminasView\ConfigProvider::class,
    new ArrayProvider(['clavia' => ['project_root' => dirname(__DIR__)]]),
    Clavia\Bootstrap\ConfigProvider::class,
])->getMergedConfig();
