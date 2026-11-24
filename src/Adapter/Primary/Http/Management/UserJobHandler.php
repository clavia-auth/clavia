<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\Jobs\ReadUserJobs;
use Clavia\Domain\Identity\Jobs\UserJobId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/jobs/{job_id}` (`getJob`): a bulk job and its report.
 */
final readonly class UserJobHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadUserJobs $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $id = UserJobId::fromString(ManagementRequest::of($request)->path('job_id'));

        return $this->responder->json(ManagementViews::userJob($this->read->one($id)));
    }
}
