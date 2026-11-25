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
use Clavia\Application\Port\OutboundUrls;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Webhook\Event\WebhookChanged;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/** `PATCH /api/v1/webhooks/{webhook_id}`: change what was sent, leave the rest. */
final readonly class UpdateWebhook
{
    public function __construct(
        private WebhookEndpointRepository $endpoints,
        private OutboundUrls $outbound,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param list<string>|null $events
     *
     * @throws NotFound
     * @throws InvalidValue
     */
    public function __invoke(
        WebhookEndpointId $id,
        ?string $url,
        ?string $description,
        ?array $events,
        ?bool $enabled,
    ): WebhookEndpoint {
        $endpoint = $this->endpoints->find($id) ?? throw NotFound::of('webhook');
        $now = $this->clock->now();

        if ($url !== null) {
            $endpoint = $endpoint->sendingTo(WebhookUrl::checked($this->outbound, $url), $now);
        }
        if ($description !== null) {
            $endpoint = $endpoint->described($description, $now);
        }
        if ($events !== null) {
            $endpoint = $endpoint->listeningTo(EventFilter::fromStrings($events), $now);
        }
        if ($enabled !== null) {
            $endpoint = $endpoint->enabled($enabled, $now);
        }
        $this->endpoints->save($endpoint);
        $this->events->dispatch(new WebhookChanged($endpoint->id, array_keys(array_filter([
            'url' => $url !== null,
            'description' => $description !== null,
            'events' => $events !== null,
            'is_enabled' => $enabled !== null,
        ]))));

        return $endpoint;
    }
}
