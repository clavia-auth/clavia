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
use Clavia\Application\Management\Webhooks\DeleteWebhook;
use Clavia\Application\Management\Webhooks\ReadWebhooks;
use Clavia\Application\Management\Webhooks\UpdateWebhook;
use Clavia\Domain\Webhook\WebhookEndpointId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|PATCH|DELETE /api/v1/webhooks/{webhook_id}`. Changing the URL or the events decides what of
 * the trail goes where, so it also needs `read:audit_events`, as creating does.
 */
final readonly class WebhookHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadWebhooks $read,
        private UpdateWebhook $update,
        private DeleteWebhook $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = WebhookEndpointId::fromString($management->path('webhook_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::webhook($this->read->one($id)));
            case 'PATCH':
                $body = $management->body;
                if ($body->has('url') || $body->has('events')) {
                    $management->caller->require(ManagementPermission::ReadAuditEvents);
                }

                return $this->responder->json(ManagementViews::webhook(($this->update)(
                    $id,
                    $body->string('url'),
                    $body->string('description'),
                    $body->strings('events'),
                    $body->bool('is_enabled'),
                )));
            case 'DELETE':
                ($this->delete)($id);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
