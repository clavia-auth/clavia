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
use Clavia\Application\Management\Webhooks\ReadWebhookDeliveries;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/webhooks/{webhook_id}/deliveries`: the endpoint's delivery log, newest first. It names
 * the audit events sent (id, type, when), a view of the trail, so it needs `read:audit_events` beside
 * `read:webhooks`, as registering and testing do.
 */
final readonly class WebhookDeliveriesHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadWebhookDeliveries $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $management->caller->require(ManagementPermission::ReadAuditEvents);
        $id = WebhookEndpointId::fromString($management->path('webhook_id'));

        return $this->responder->json(ManagementViews::page(
            ($this->read)($id, Paging::fromRequest($management)),
            ManagementViews::webhookDelivery(...),
        ));
    }
}
