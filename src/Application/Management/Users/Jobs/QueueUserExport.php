<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;

/**
 * `POST /api/v1/jobs/users-exports`: queue an export of the accounts of one connection, any kind of
 * it, for `clavia jobs:run` ({@see RunUserJobs}), which writes them out
 * ({@see \Clavia\Application\Management\Users\Export\ExportUsers}).
 */
final readonly class QueueUserExport
{
    public function __construct(
        private UserJobRepository $jobs,
        private ConnectionRepository $connections,
        private AuditContext $audit,
        private RandomSource $random,
        private Clock $clock,
    ) {
    }

    /**
     * @param string|null $connection The connection; null for the default pool.
     *
     * @throws NotFound When the connection does not exist.
     */
    public function __invoke(?string $connection): UserJob
    {
        $name = $connection === null
            ? ConnectionName::defaultPool()
            : ReadConnections::find($this->connections, $connection)->name;

        $job = UserJob::queueExport(
            UserJobId::generate($this->random),
            $name,
            // The caller the Management API authenticated: the export is recorded as theirs.
            $this->audit->actor() ?? Actor::system(),
            $this->clock->now(),
        );
        $this->jobs->add($job);

        return $job;
    }
}
