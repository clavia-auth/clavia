<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\DeliveryFailure;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use Clavia\Domain\Webhook\WebhookDeliveryStatus;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/** The webhook outbox, the double and PostgreSQL alike (docs/design/webhooks.md §4, §5.2, §5.3). */
trait WebhookDeliveryRepositoryContract
{
    abstract protected function auditLog(): AuditLog;

    abstract protected function webhookEndpoints(): WebhookEndpointRepository;

    abstract protected function webhookDeliveries(): WebhookDeliveryRepository;

    #[Test]
    public function anEventIsQueuedForTheEnabledEndpointsListeningToIt(): void
    {
        $all = $this->anEndpoint(1, EventFilter::all());
        $users = $this->anEndpoint(2, EventFilter::fromStrings(['user.created']));
        $this->anEndpoint(3, EventFilter::fromStrings(['role.created']));
        $off = $this->anEndpoint(4, EventFilter::all());
        $this->webhookEndpoints()->save($off->enabled(false, new DateTimeImmutable()));

        $event = $this->anEvent(1, AuditEventType::UserCreated);
        $queued = $this->webhookDeliveries()->enqueueFor($event, self::at('10:00'));

        self::assertSame(2, $queued);
        self::assertCount(1, $this->webhookDeliveries()->due($all->id, self::at('10:00'), 10));
        self::assertCount(1, $this->webhookDeliveries()->due($users->id, self::at('10:00'), 10));
        self::assertSame([], $this->webhookDeliveries()->due($off->id, self::at('10:00'), 10));
    }

    #[Test]
    public function anEndpointIsClaimedByOneWorkerUntilReleasedOrLapsed(): void
    {
        $endpoint = $this->anEndpoint(1, EventFilter::all());
        $this->webhookDeliveries()->enqueueFor($this->anEvent(1, AuditEventType::UserCreated), self::at('10:00'));

        $first = $this->webhookDeliveries()->claimEndpoints(self::at('10:00'), self::at('10:01'), 10);
        $second = $this->webhookDeliveries()->claimEndpoints(self::at('10:00'), self::at('10:01'), 10);
        $lapsed = $this->webhookDeliveries()->claimEndpoints(self::at('10:02'), self::at('10:03'), 10);
        $this->webhookDeliveries()->release($endpoint->id);
        $released = $this->webhookDeliveries()->claimEndpoints(self::at('10:02'), self::at('10:03'), 10);

        self::assertSame(
            [$endpoint->id->value],
            array_map(static fn (WebhookEndpointId $id): string => $id->value, $first),
        );
        self::assertSame([], $second, 'Claimed: another worker gets nothing.');
        self::assertCount(1, $lapsed, 'A claim that lapsed is taken again.');
        self::assertCount(1, $released);
    }

    #[Test]
    public function anAttemptIsSavedAndAnEndedDeliveryPurged(): void
    {
        $endpoint = $this->anEndpoint(1, EventFilter::all());
        $this->webhookDeliveries()->enqueueFor($this->anEvent(1, AuditEventType::UserCreated), self::at('10:00'));
        $this->webhookDeliveries()->enqueueFor($this->anEvent(2, AuditEventType::UserDeleted), self::at('10:00'));
        $due = $this->webhookDeliveries()->due($endpoint->id, self::at('10:00'), 10);
        self::assertCount(2, $due);
        [$created, $deleted] = [$due[0], $due[1] ?? $due[0]];

        $this->webhookDeliveries()->save($created->succeeded(200, 30, self::at('10:00')));
        $this->webhookDeliveries()->save($deleted->failed(
            DeliveryFailure::Status,
            500,
            30,
            self::at('10:00'),
            new SeededRandomSource(1),
        ));

        self::assertSame(
            [],
            $this->webhookDeliveries()->due($endpoint->id, self::at('10:00'), 10),
            'The retry is not due yet.',
        );
        $retry = $this->webhookDeliveries()->due($endpoint->id, self::at('10:01'), 10);
        self::assertCount(1, $retry);
        self::assertSame(WebhookDeliveryStatus::Pending, $retry[0]->status);
        self::assertSame([1, 500], [$retry[0]->attempts, $retry[0]->lastStatusCode]);

        self::assertSame(0, $this->webhookDeliveries()->purgeEndedBefore(self::at('10:00')));
        self::assertSame(1, $this->webhookDeliveries()->purgeEndedBefore(self::at('10:05')), 'The success only.');
    }

    private function anEndpoint(int $seed, EventFilter $events): WebhookEndpoint
    {
        $endpoint = WebhookEndpoint::register(
            WebhookEndpointId::generate(new SeededRandomSource(100 + $seed)),
            Url::fromString('https://hooks' . $seed . '.example/audit'),
            '',
            $events,
            'sealed',
            self::at('09:0' . $seed),
        );
        $this->webhookEndpoints()->save($endpoint);

        return $endpoint;
    }

    private function anEvent(int $seed, AuditEventType $type): AuditEvent
    {
        $event = AuditEvent::record(
            AuditEventId::generate(new SeededRandomSource(200 + $seed)),
            $type,
            self::at('10:00'),
            Actor::system(),
            null,
            Outcome::Success,
        );
        $this->auditLog()->append($event);

        return $event;
    }

    private static function at(string $time): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T' . $time . ':00Z');
    }
}
