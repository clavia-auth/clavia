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
use Clavia\Application\Management\Webhooks\ReadWebhooks;
use Clavia\Application\Management\Webhooks\RegisterWebhook;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /api/v1/webhooks` (`listWebhooks`, `createWebhook`). Creating one streams the audit
 * trail to it, so it also needs `read:audit_events`: without it, a caller who may not read the trail
 * could read it anyway by pointing an endpoint at itself (docs/design/webhooks.md §2).
 */
final readonly class WebhooksHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadWebhooks $read,
        private RegisterWebhook $register,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);

        switch ($request->getMethod()) {
            case RequestMethodInterface::METHOD_GET:
                return $this->responder->jsonList(array_map(
                    static fn (WebhookEndpoint $endpoint): array => ManagementViews::webhook($endpoint),
                    $this->read->all(),
                ));
            case RequestMethodInterface::METHOD_POST:
                $management->caller->require(ManagementPermission::ReadAuditEvents);
                $body = $management->body;
                $created = ($this->register)(
                    (string) $body->string('url'),
                    $body->string('description') ?? '',
                    $body->strings('events') ?? [],
                );

                return $this->responder->created(
                    ManagementViews::webhookWithSecret($created),
                    '/api/v1/webhooks/' . $created->endpoint->id->value,
                );
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
