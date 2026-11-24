<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

use DateTimeImmutable;

/**
 * The bulk jobs on the users, and the queue they wait in.
 */
interface UserJobRepository
{
    public function add(UserJob $job): void;

    public function find(UserJobId $id): ?UserJob;

    /** Record the job's progress, its report and its end. */
    public function save(UserJob $job): void;

    /**
     * The oldest queued job, now running: taken in one statement that two workers can never both
     * win (`FOR UPDATE SKIP LOCKED`), so a job runs once however many workers run.
     */
    public function claimNext(DateTimeImmutable $now): ?UserJob;

    /**
     * The jobs still running that started before `$startedBefore`: their worker died with them.
     *
     * @return list<UserJob>
     */
    public function runningSince(DateTimeImmutable $startedBefore): array;

    /**
     * Delete the jobs finished before `$before`, report and all.
     *
     * @return non-negative-int How many.
     */
    public function purgeFinishedBefore(DateTimeImmutable $before): int;
}
