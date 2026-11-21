<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientRepository;
use Clavia\Application\Port\TransactionManager;
use Psr\Container\ContainerInterface;

final class ClientRepositoryFactory
{
    public function __invoke(ContainerInterface $container): PhpDbClientRepository
    {
        /** @var Database $database */
        $database = $container->get(Database::class);

        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);

        return new PhpDbClientRepository($database, $transactions);
    }
}
