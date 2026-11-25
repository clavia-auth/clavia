<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\TargetType;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Webhook\WebhookDelivery;
use Clavia\Domain\Webhook\WebhookDeliveryId;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookDeliveryStatus;
use Clavia\Domain\Webhook\WebhookEndpointId;
use DateTimeImmutable;

/**
 * The outbox in memory, queuing against the endpoints the double holds, claiming endpoints as the
 * database does. With no endpoints, it queues nothing.
 */
final class InMemoryWebhookDeliveryRepository implements WebhookDeliveryRepository
{
    /** @var array<string, WebhookDelivery> By id, in the order queued. */
    private array $deliveries = [];

    /** @var array<string, DateTimeImmutable> Claims, by endpoint id. */
    private array $claims = [];

    public function __construct(
        private readonly InMemoryWebhookEndpointRepository $endpoints = new InMemoryWebhookEndpointRepository(),
        private readonly SeededRandomSource $random = new SeededRandomSource(99),
    ) {
    }

    #[\Override]
    public function enqueueFor(AuditEvent $event, DateTimeImmutable $now): int
    {
        $queued = 0;
        $tested = $event->type === AuditEventType::WebhookTested;
        foreach ($this->endpoints->all() as $endpoint) {
            $wanted = $tested
                ? $event->target?->type === TargetType::Webhook && $event->target->id === $endpoint->id->value
                : $endpoint->events->matches($event->type);
            if (! $endpoint->isEnabled || ! $wanted) {
                continue;
            }
            $delivery = WebhookDelivery::reconstitute(
                WebhookDeliveryId::generate($this->random),
                $endpoint->id,
                $event->id,
                $event->type,
                WebhookDeliveryStatus::Pending,
                0,
                $now,
                null,
                null,
                null,
                $now,
                null,
            );
            $this->deliveries[$delivery->id->value] = $delivery;
            ++$queued;
        }

        return $queued;
    }

    #[\Override]
    public function claimEndpoints(DateTimeImmutable $now, DateTimeImmutable $until, int $limit): array
    {
        $claimed = [];
        foreach ($this->endpoints->all() as $endpoint) {
            if (count($claimed) >= $limit) {
                break;
            }
            $free = ! isset($this->claims[$endpoint->id->value]) || $this->claims[$endpoint->id->value] < $now;
            if ($free && $this->due($endpoint->id, $now, 1) !== []) {
                $this->claims[$endpoint->id->value] = $until;
                $claimed[] = $endpoint->id;
            }
        }

        return $claimed;
    }

    #[\Override]
    public function due(WebhookEndpointId $endpoint, DateTimeImmutable $now, int $limit): array
    {
        $due = array_values(array_filter(
            $this->deliveries,
            static fn (WebhookDelivery $d): bool => $d->endpointId->equals($endpoint)
                && $d->status === WebhookDeliveryStatus::Pending
                && $d->nextAttemptAt <= $now,
        ));

        return array_slice($due, 0, $limit);
    }

    #[\Override]
    public function save(WebhookDelivery $delivery): void
    {
        if (isset($this->deliveries[$delivery->id->value])) {
            $this->deliveries[$delivery->id->value] = $delivery;
        }
    }

    #[\Override]
    public function page(WebhookEndpointId $endpoint, PageRequest $request): Page
    {
        $mine = array_values(array_filter(
            $this->deliveries,
            static fn (WebhookDelivery $d): bool => $d->endpointId->equals($endpoint),
        ));
        usort(
            $mine,
            static fn (WebhookDelivery $a, WebhookDelivery $b): int
                => [$b->createdAt, $b->id->value] <=> [$a->createdAt, $a->id->value],
        );

        return new Page(array_slice($mine, $request->offset(), $request->perPage), count($mine), $request);
    }

    #[\Override]
    public function release(WebhookEndpointId $endpoint): void
    {
        unset($this->claims[$endpoint->value]);
    }

    #[\Override]
    public function purgeEndedBefore(DateTimeImmutable $before): int
    {
        $purged = 0;
        foreach ($this->deliveries as $key => $delivery) {
            if ($delivery->endedAt !== null && $delivery->endedAt < $before) {
                unset($this->deliveries[$key]);
                ++$purged;
            }
        }

        return $purged;
    }

    /** @return list<WebhookDelivery> Every delivery, for a test to look at. */
    public function all(): array
    {
        return array_values($this->deliveries);
    }
}
