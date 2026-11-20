<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Infrastructure\Persistence\PhpDb\Database;
use Clavia\Infrastructure\Persistence\PhpDb\PhpDbUserRepository;
use Psr\Container\ContainerInterface;

final class UserRepositoryFactory
{
    public function __invoke(ContainerInterface $container): PhpDbUserRepository
    {
        /** @var Database $database */
        $database = $container->get(Database::class);

        return new PhpDbUserRepository($database);
    }
}
