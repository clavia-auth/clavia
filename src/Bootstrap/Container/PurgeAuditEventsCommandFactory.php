<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\PurgeAuditEventsCommand;
use Clavia\Application\Audit\PurgeAuditEvents;
use Psr\Container\ContainerInterface;

final class PurgeAuditEventsCommandFactory
{
    public function __invoke(ContainerInterface $container): PurgeAuditEventsCommand
    {
        /** @var PurgeAuditEvents $purge */
        $purge = $container->get(PurgeAuditEvents::class);

        return new PurgeAuditEventsCommand($purge);
    }
}
