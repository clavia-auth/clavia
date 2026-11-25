<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Webhooks\TestWebhook;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /api/v1/webhooks/{webhook_id}/test`: a test delivery queued, `202`. Like registering an
 * endpoint, it needs `read:audit_events` beside `update:webhooks`: what it sends is an audit event.
 */
final readonly class WebhookTestHandler implements RequestHandlerInterface
{
    public function __construct(
        private TestWebhook $test,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $management->caller->require(ManagementPermission::ReadAuditEvents);
        ($this->test)(WebhookEndpointId::fromString($management->path('webhook_id')));

        return $this->responder->accepted();
    }
}
