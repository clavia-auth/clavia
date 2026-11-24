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
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * `POST /api/v1/jobs/users-imports`: queue an import of accounts, NDJSON, into one pool, for
 * `clavia jobs:run` ({@see RunUserJobs}). Nothing is read line by line here: a bad line is refused
 * in the job's report, never by refusing the whole file.
 *
 * Only a pool takes accounts this way: the accounts of a social or OpenID Connect connection are
 * made by signing in through it.
 */
final readonly class QueueUserImport
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
     * @param string|null $connection The pool; null for the default one.
     * @param string      $input      NDJSON: one account per line.
     *
     * @throws NotFound     When the connection does not exist.
     * @throws InvalidValue When it is not a pool, or the input is empty or too large.
     */
    public function __invoke(?string $connection, #[\SensitiveParameter] string $input): UserJob
    {
        $pool = $connection === null
            ? ConnectionName::defaultPool()
            : ReadConnections::find($this->connections, $connection)->name;
        if (! ($this->connections->find($pool)?->isDatabase() ?? false)) {
            throw new InvalidValue(sprintf(
                "Accounts are imported into a pool; '%s' is not one.",
                $pool->value,
            ));
        }
        $lines = array_filter(
            preg_split('/\r?\n/', $input) ?: [],
            static fn (string $line): bool => trim($line) !== '',
        );
        if (count($lines) > UserJob::MAX_LINES) {
            throw new InvalidValue(
                sprintf('An import is at most %d lines; split it into several.', UserJob::MAX_LINES),
            );
        }

        $job = UserJob::queueImport(
            UserJobId::generate($this->random),
            $pool,
            $input,
            // The caller the Management API authenticated: the accounts are recorded as theirs.
            $this->audit->actor() ?? Actor::system(),
            $this->clock->now(),
        );
        $this->jobs->add($job);

        return $job;
    }
}
