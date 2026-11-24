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
use Clavia\Application\Management\Users\Export\ExportUsers;
use Clavia\Application\Management\Users\Import\ImportRefusal;
use Clavia\Application\Management\Users\Import\UserImport;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\Event\UsersExported;
use Clavia\Domain\Identity\Jobs\LineError;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobKind;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `clavia jobs:run`: runs the queued bulk jobs on the users, one after another, then exits. Meant
 * for a scheduler, every minute; two runs at once never share a job ({@see UserJobRepository::claimNext()}).
 *
 * An import takes its lines in order, each through the {@see UserImport} port, the rules every way in
 * shares: a refused line (unreadable, a field the API would refuse, an address already in the pool)
 * is reported by number and the rest carry on. Each account is recorded in the trail as the work of
 * whoever queued the job. An export writes the accounts of its connection out, never with a hash,
 * and keeps the output with the job; the trail records it as `user.exported`.
 *
 * Before taking new work it fails the jobs still running past {@see STALL_AFTER_SECONDS}, whose worker
 * stopped; after, it deletes the jobs finished more than {@see RETENTION_DAYS} days ago.
 */
final readonly class RunUserJobs
{
    /** A job running longer than this has lost its worker: 10,000 lines take seconds. */
    public const int STALL_AFTER_SECONDS = 3600;

    /** How long a finished job's report is kept. */
    public const int RETENTION_DAYS = 7;

    /** The report is saved every so many lines, so a reader sees it move. */
    private const int SAVE_EVERY = 100;

    private const string STOPPED = 'The worker running it stopped before the end;';

    public function __construct(
        private UserJobRepository $jobs,
        private UserImport $imports,
        private ExportUsers $exports,
        private TransactionManager $transactions,
        private AuditContext $audit,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(): JobsRun
    {
        $stalled = 0;
        $now = $this->clock->now();
        foreach ($this->jobs->runningSince($now->modify(sprintf('-%d seconds', self::STALL_AFTER_SECONDS))) as $job) {
            $job->fail(match ($job->kind) {
                UserJobKind::Import => self::STOPPED . ' queue the lines it did not take again.',
                UserJobKind::Export => self::STOPPED . ' queue the export again.',
            }, $now);
            $this->jobs->save($job);
            ++$stalled;
        }

        $completed = 0;
        while (($job = $this->jobs->claimNext($this->clock->now())) !== null) {
            match ($job->kind) {
                UserJobKind::Import => $this->import($job),
                UserJobKind::Export => $this->export($job),
            };
            ++$completed;
        }

        $purged = $this->jobs->purgeFinishedBefore(
            $this->clock->now()->modify(sprintf('-%d days', self::RETENTION_DAYS)),
        );

        return new JobsRun($completed, $stalled, $purged);
    }

    /**
     * The accounts written out, then, in one transaction, the job completed, its output kept, and the
     * export announced: a job is never completed without its output, nor the reverse.
     */
    private function export(UserJob $job): void
    {
        $this->audit->actAs($job->requestedBy);
        $exported = ($this->exports)($job->connection);
        $this->transactions->transactional(function () use ($job, $exported): void {
            $job->completeExport($exported->count, $this->clock->now());
            $this->jobs->save($job);
            $this->jobs->writeOutput($job->id, $exported->content);
            $this->events->dispatch(new UsersExported($job->id, $job->connection, $exported->count));
        });
    }

    private function import(UserJob $job): void
    {
        $this->audit->actAs($job->requestedBy);
        $number = 0;
        foreach (preg_split('/\r?\n/', $job->input() ?? '') ?: [] as $line) {
            ++$number;
            if (trim($line) === '') {
                continue;
            }
            $outcome = $this->imports->import($line, $job->connection);
            $outcome instanceof ImportRefusal
                ? $job->recordRefused(new LineError($number, $outcome->error, $outcome->detail))
                : $job->recordCreated();
            if ($job->total() % self::SAVE_EVERY === 0) {
                $this->jobs->save($job);
            }
        }

        $job->complete($this->clock->now());
        $this->jobs->save($job);
    }
}
