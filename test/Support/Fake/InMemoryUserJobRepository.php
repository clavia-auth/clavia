<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\Jobs\UserJobStatus;
use DateTimeImmutable;

/**
 * Bulk jobs in memory, copied on the way in and out like storage: a job changes only once saved.
 */
final class InMemoryUserJobRepository implements UserJobRepository
{
    /** @var array<string, UserJob> By id, in insertion order. */
    private array $jobs = [];

    #[\Override]
    public function add(UserJob $job): void
    {
        $this->jobs[$job->id->value] = clone $job;
    }

    #[\Override]
    public function find(UserJobId $id): ?UserJob
    {
        $job = $this->jobs[$id->value] ?? null;

        return $job === null ? null : clone $job;
    }

    #[\Override]
    public function save(UserJob $job): void
    {
        if (isset($this->jobs[$job->id->value])) {
            $this->jobs[$job->id->value] = clone $job;
        }
    }

    #[\Override]
    public function claimNext(DateTimeImmutable $now): ?UserJob
    {
        $queued = array_filter($this->jobs, static fn (UserJob $job): bool => $job->status() === UserJobStatus::Queued);
        uasort($queued, static fn (UserJob $a, UserJob $b): int => $a->createdAt <=> $b->createdAt);
        $next = reset($queued);
        if ($next === false) {
            return null;
        }
        $next->start($now);

        return clone $next;
    }

    #[\Override]
    public function runningSince(DateTimeImmutable $startedBefore): array
    {
        return array_values(array_map(static fn (UserJob $job): UserJob => clone $job, array_filter(
            $this->jobs,
            static fn (UserJob $job): bool => $job->status() === UserJobStatus::Running
                && $job->startedAt() < $startedBefore,
        )));
    }

    #[\Override]
    public function purgeFinishedBefore(DateTimeImmutable $before): int
    {
        $purged = 0;
        foreach ($this->jobs as $key => $job) {
            if ($job->isFinished() && $job->finishedAt() < $before) {
                unset($this->jobs[$key]);
                ++$purged;
            }
        }

        return $purged;
    }
}
