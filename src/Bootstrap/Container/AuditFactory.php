<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Audit\AuditContext;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class AuditFactory
{
    public function __invoke(ContainerInterface $container): Audit
    {
        /** @var AuditLog $log */
        $log = $container->get(AuditLog::class);
        /** @var AuditContext $context */
        $context = $container->get(AuditContext::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);

        return new Audit($log, $context, $clock, $random);
    }
}
