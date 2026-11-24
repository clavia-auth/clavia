<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Identity\Jobs\UserJob;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Clavia\Domain\Identity\Jobs\UserJobRepository;

/**
 * `GET /api/v1/jobs/{job_id}`: a bulk job, where it stands, and its report.
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
}
