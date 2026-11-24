<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\ImportUsersFromSqsCommand;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessagesFactory;
use Clavia\Application\Management\Users\Import\UserImport;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final class ImportUsersFromSqsCommandFactory
{
    public function __invoke(ContainerInterface $container): ImportUsersFromSqsCommand
    {
        /** @var QueueMessagesFactory $queues */
        $queues = $container->get(QueueMessagesFactory::class);
        /** @var UserImport $imports */
        $imports = $container->get(UserImport::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new ImportUsersFromSqsCommand($queues, $imports, $logger);
    }
}
