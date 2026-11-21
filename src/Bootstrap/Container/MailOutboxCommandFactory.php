<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\MailOutboxCommand;
use Clavia\Application\Port\MailOutbox;
use Psr\Container\ContainerInterface;

final class MailOutboxCommandFactory
{
    public function __invoke(ContainerInterface $container): MailOutboxCommand
    {
        /** @var MailOutbox $outbox */
        $outbox = $container->get(MailOutbox::class);

        return new MailOutboxCommand($outbox);
    }
}
