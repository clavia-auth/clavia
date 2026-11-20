<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use Clavia\Infrastructure\Persistence\PhpDb\Database;
use Clavia\Infrastructure\Persistence\PhpDb\PostgresUrl;
use Psr\Container\ContainerInterface;

final class DatabaseFactory
{
    public function __invoke(ContainerInterface $container): Database
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        // Lazy: this opens no connection. A request that needs no database never opens one.
        return new Database(PostgresUrl::parse($settings->databaseUrl));
    }
}
