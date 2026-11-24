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
use Clavia\Application\Management\Users\Import\UserImport;
use Clavia\Application\Management\Users\Jobs\RunUserJobs;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class RunUserJobsFactory
{
    public function __invoke(ContainerInterface $container): RunUserJobs
    {
        /** @var UserJobRepository $jobs */
        $jobs = $container->get(UserJobRepository::class);
        /** @var UserImport $imports */
        $imports = $container->get(UserImport::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new RunUserJobs($jobs, $imports, $audit, $clock);
    }
}
