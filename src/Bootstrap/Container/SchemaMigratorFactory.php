<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Domain\Shared\Clock;
use Clavia\Adapter\Secondary\Persistence\Migrations\SqlFileMigrator;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Psr\Container\ContainerInterface;

final class SchemaMigratorFactory
{
    public function __invoke(ContainerInterface $container): SqlFileMigrator
    {
        /** @var array{clavia: array{project_root: string}} $config */
        $config = $container->get('config');
        /** @var Database $database */
        $database = $container->get(Database::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new SqlFileMigrator($database, $config['clavia']['project_root'] . '/migrations', $clock);
    }
}
