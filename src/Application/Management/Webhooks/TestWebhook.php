<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Webhook\Event\WebhookTested;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/**
 * `POST /api/v1/webhooks/{id}/test` (docs/design/webhooks.md §5.4): records `webhook.tested`, which
 * the outbox queues for that endpoint alone, so the worker sends it as it sends everything: the same
 * envelope, signature and checks. An operator checks a receiver without waiting for a real event.
 */
final readonly class TestWebhook
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private TransactionManager $transactions,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws Conflict The endpoint is switched off: nothing would be sent.
     */
    public function __invoke(WebhookEndpointId $id): void
    {
        $this->transactions->transactional(function () use ($id): void {
            $endpoint = $this->endpoints->find($id) ?? throw NotFound::of('webhook');
            if (! $endpoint->isEnabled) {
                throw new Conflict('The webhook is switched off: enable it to test it.');
            }
            $this->events->dispatch(new WebhookTested($id));
        });
    }
}
