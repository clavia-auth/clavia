<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\PurgeAuditEvents;
use Clavia\Configuration\Settings;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class PurgeAuditEventsFactory
{
    public function __invoke(ContainerInterface $container): PurgeAuditEvents
    {
        /** @var AuditLog $log */
        $log = $container->get(AuditLog::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $retention = $settings->auditRetentionDays;
        assert($retention > 0);

        return new PurgeAuditEvents($log, $clock, $retention);
    }
}
