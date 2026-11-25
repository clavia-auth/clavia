<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Webhook\Event\WebhookSecretRotated;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/**
 * `POST /api/v1/webhooks/{webhook_id}/rotate-secret`: a new secret, returned once; the previous one
 * signs beside it for {@see WebhookEndpoint::ROTATION_OVERLAP_SECONDS}, so a receiver can switch
 * without missing a delivery.
 */
final readonly class RotateWebhookSecret
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private WebhookSecrets $secrets,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /** @throws NotFound */
    public function __invoke(WebhookEndpointId $id): WebhookWithSecret
    {
        $endpoint = $this->endpoints->find($id) ?? throw NotFound::of('webhook');
        $secret = $this->secrets->generate();
        $rotated = $endpoint->rotatedTo($this->secrets->seal($id, $secret), $this->clock->now());
        $this->endpoints->save($rotated);
        $this->events->dispatch(new WebhookSecretRotated($id));

        return new WebhookWithSecret($rotated, $secret);
    }
}
