<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Users\Jobs\QueueUserExport;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /api/v1/jobs/users-exports` (`exportUsers`): the connection a query parameter, no body.
 * Answers `202` with the queued job, which `clavia jobs:run` takes.
 */
final readonly class UserExportsHandler implements RequestHandlerInterface
{
    public function __construct(
        private QueueUserExport $queue,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $connection */
        $connection = ManagementRequest::of($request)->query('connection');
        $job = ($this->queue)(is_string($connection) ? $connection : null);

        return $this->responder->json(ManagementViews::userJob($job), 202)
            ->withHeader('Location', '/api/v1/jobs/' . $job->id->value);
    }
}
