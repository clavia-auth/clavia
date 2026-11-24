<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobKind;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\Jobs\UserJobStatus;

/**
 * `GET /api/v1/jobs/{job_id}`: a bulk job, where it stands, and its report; and an export's output.
 */
final readonly class ReadUserJobs
{
    public function __construct(private UserJobRepository $jobs)
    {
    }

    /**
     * @throws NotFound
     */
    public function one(UserJobId $id): UserJob
    {
        return $this->jobs->find($id) ?? throw NotFound::of('job');
    }

    /**
     * `GET /api/v1/jobs/{job_id}/output`: what a completed export wrote.
     *
     * @throws NotFound When there is no such job, or it is an import, which writes nothing.
     * @throws Conflict When the export is not completed: queued, running or failed.
     */
    public function output(UserJobId $id): string
    {
        $job = $this->one($id);
        if ($job->kind !== UserJobKind::Export) {
            throw NotFound::of('output: an import writes none');
        }
        if ($job->status() !== UserJobStatus::Completed) {
            throw new Conflict('The export is not completed: follow the job until it is.');
        }

        return $this->jobs->output($id) ?? throw NotFound::of('output');
    }
}
