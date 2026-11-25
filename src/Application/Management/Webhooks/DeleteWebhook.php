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
use Clavia\Domain\Webhook\Event\WebhookDeleted;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/** `DELETE /api/v1/webhooks/{webhook_id}`: nothing more is sent to it. */
final readonly class DeleteWebhook
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private DomainEvents $events,
    ) {
    }

    /** @throws NotFound */
    public function __invoke(WebhookEndpointId $id): void
    {
        $endpoint = $this->endpoints->find($id) ?? throw NotFound::of('webhook');
        $this->endpoints->delete($id);
        $this->events->dispatch(new WebhookDeleted($endpoint));
    }
}
