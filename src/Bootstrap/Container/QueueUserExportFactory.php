<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Users\Jobs\QueueUserExport;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class QueueUserExportFactory
{
    public function __invoke(ContainerInterface $container): QueueUserExport
    {
        /** @var UserJobRepository $jobs */
        $jobs = $container->get(UserJobRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new QueueUserExport($jobs, $connections, $audit, $random, $clock);
    }
}
