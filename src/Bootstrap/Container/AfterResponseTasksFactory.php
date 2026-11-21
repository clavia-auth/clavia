<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\System\AfterResponseTasks;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final class AfterResponseTasksFactory
{
    public function __invoke(ContainerInterface $container): AfterResponseTasks
    {
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new AfterResponseTasks($logger);
    }
}
