<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Webhooks\RotateWebhookSecret;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** `POST /api/v1/webhooks/{webhook_id}/rotate-secret` (`rotateWebhookSecret`): the new secret, once. */
final readonly class WebhookSecretHandler implements RequestHandlerInterface
{
    public function __construct(
        private RotateWebhookSecret $rotate,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $id = WebhookEndpointId::fromString(ManagementRequest::of($request)->path('webhook_id'));

        return $this->responder->json(ManagementViews::webhookWithSecret(($this->rotate)($id)));
    }
}
