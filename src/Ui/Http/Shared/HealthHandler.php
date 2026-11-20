<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Http\Shared;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /healthz` — liveness: the process is up and can route a request.
 *
 * Deliberately touches neither PostgreSQL nor Redis: an orchestrator that restarts the
 * server because a dependency blinked makes an outage worse.
 */
final readonly class HealthHandler implements RequestHandlerInterface
{
    public function __construct(
        private JsonResponder $json,
        private string $version,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->json->respond(200, ['status' => 'ok', 'version' => $this->version]);
    }
}
