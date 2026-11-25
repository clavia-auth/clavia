<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookDisabledReason;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/** What every {@see WebhookEndpointRepository} keeps of an endpoint, the double and PostgreSQL alike. */
trait WebhookEndpointRepositoryContract
{
    abstract protected function webhookEndpoints(): WebhookEndpointRepository;

    #[Test]
    public function anEndpointIsKeptWholeThroughARotation(): void
    {
        $endpoint = $this->anEndpoint(1, '2026-01-15T10:00:00Z');
        $this->webhookEndpoints()->save($endpoint);
        $read = $this->webhookEndpoints()->find($endpoint->id);
        self::assertNotNull($read);
        self::assertSame('https://hooks.example/audit?k=1', $read->url->value);
        self::assertSame('SIEM', $read->description);
        self::assertSame(['user.created', 'user.deleted'], $read->events->toStrings());
        self::assertTrue($read->isEnabled);
        self::assertSame('sealed-1', $read->sealedSecret);
        self::assertNull($read->sealedPreviousSecret);

        $now = new DateTimeImmutable('2026-01-16T10:00:00Z');
        $this->webhookEndpoints()->save(
            $read->rotatedTo('sealed-2', $now)->enabled(false, $now)->listeningTo(EventFilter::all(), $now),
        );

        $rotated = $this->webhookEndpoints()->find($endpoint->id);
        self::assertNotNull($rotated);
        self::assertSame('sealed-2', $rotated->sealedSecret);
        self::assertSame('sealed-1', $rotated->previousSecretAt($now));
        self::assertNull($rotated->previousSecretAt(new DateTimeImmutable('2026-01-17T10:00:01Z')));
        self::assertFalse($rotated->isEnabled);
        self::assertSame(['*'], $rotated->events->toStrings());
        self::assertEquals($now, $rotated->updatedAt);
    }

    #[Test]
    public function endpointsAreListedOldestFirstCountedAndDeleted(): void
    {
        $late = $this->anEndpoint(2, '2026-01-15T12:00:00Z');
        $early = $this->anEndpoint(3, '2026-01-15T09:00:00Z');
        $this->webhookEndpoints()->save($late);
        $this->webhookEndpoints()->save($early);

        self::assertSame(2, $this->webhookEndpoints()->count());
        self::assertSame(
            [$early->id->value, $late->id->value],
            array_map(static fn (WebhookEndpoint $e): string => $e->id->value, $this->webhookEndpoints()->all()),
        );

        $this->webhookEndpoints()->delete($early->id);
        self::assertNull($this->webhookEndpoints()->find($early->id));
        self::assertSame(1, $this->webhookEndpoints()->count());
    }

    #[Test]
    public function anEndpointFailingFiveDaysIsSwitchedOffOnce(): void
    {
        $endpoint = $this->anEndpoint(7, '2026-02-01T10:00:00Z');
        $repository = $this->webhookEndpoints();
        $repository->save($endpoint);
        $start = new DateTimeImmutable('2026-03-01T10:00:00Z');

        $repository->recordFailure($endpoint->id, $start);
        $repository->recordFailure($endpoint->id, $start->modify('+1 day'));
        self::assertEquals($start, $repository->find($endpoint->id)?->failingSince, 'The first failure counts.');
        $found = $repository->find($endpoint->id);
        self::assertNotNull($found);
        $repository->save($found->described('Renamed', $start->modify('+2 days')));
        self::assertEquals($start, $repository->find($endpoint->id)?->failingSince, 'Another change keeps the clock.');

        self::assertFalse($repository->disableIfFailingSince($endpoint->id, $start->modify('-1 second'), $start));
        self::assertTrue($repository->disableIfFailingSince($endpoint->id, $start, $start->modify('+5 days')));
        $again = $repository->disableIfFailingSince($endpoint->id, $start, $start->modify('+5 days'));
        self::assertFalse($again, 'Once.');
        $off = $repository->find($endpoint->id);
        self::assertNotNull($off);
        self::assertFalse($off->isEnabled);
        self::assertSame(WebhookDisabledReason::Failing, $off->disabledReason);

        $repository->save($off->enabled(true, $start->modify('+6 days')));
        $on = $repository->find($endpoint->id);
        self::assertNotNull($on);
        self::assertTrue($on->isEnabled);
        self::assertNull($on->disabledReason);
        self::assertNull($on->failingSince, 'Switched on again, it is given five days again.');
    }

    #[Test]
    public function aSuccessStopsTheFailureClock(): void
    {
        $endpoint = $this->anEndpoint(7, '2026-02-01T10:00:00Z');
        $this->webhookEndpoints()->save($endpoint);
        $this->webhookEndpoints()->recordFailure($endpoint->id, new DateTimeImmutable('2026-03-01T10:00:00Z'));

        $this->webhookEndpoints()->recordSuccess($endpoint->id);

        self::assertNull($this->webhookEndpoints()->find($endpoint->id)?->failingSince);
    }

    private function anEndpoint(int $seed, string $at): WebhookEndpoint
    {
        return WebhookEndpoint::register(
            WebhookEndpointId::generate(new SeededRandomSource($seed)),
            Url::fromString('https://hooks.example/audit?k=1'),
            'SIEM',
            EventFilter::fromStrings([AuditEventType::UserDeleted->value, AuditEventType::UserCreated->value]),
            'sealed-' . $seed,
            new DateTimeImmutable($at),
        );
    }
}
