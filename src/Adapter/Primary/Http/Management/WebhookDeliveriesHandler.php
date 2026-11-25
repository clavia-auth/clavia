<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Webhooks\ReadWebhookDeliveries;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** `GET /api/v1/webhooks/{webhook_id}/deliveries`: the endpoint's delivery log, newest first. */
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
        $id = WebhookEndpointId::fromString($management->path('webhook_id'));

        return $this->responder->json(ManagementViews::page(
            ($this->read)($id, Paging::fromRequest($management)),
            ManagementViews::webhookDelivery(...),
        ));
    }
}
