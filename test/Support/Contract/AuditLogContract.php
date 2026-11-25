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
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every audit log does: keeps an event whole, reads it back newest first and filtered,
 * and forgets only what is past retention.
 */
trait AuditLogContract
{
    abstract protected function auditLog(): AuditLog;

    #[Test]
    public function anEventIsReadBackWhole(): void
    {
        $ada = UserId::generate(new SeededRandomSource(1));
        $event = AuditEvent::record(
            AuditEventId::generate(new SeededRandomSource(2)),
            AuditEventType::SignedIn,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            Actor::person($ada, ClientId::fromString('dashboard')),
            AuditTarget::user($ada),
            Outcome::Success,
            ['method' => 'pwd', 'amr' => ['pwd', 'otp'], 'remembered' => false, 'attempt' => 2],
            '198.51.100.7',
            'Mozilla/5.0',
        );

        $this->auditLog()->append($event);

        self::assertEquals([$event], $this->auditLog()->page(new AuditQuery(), PageRequest::of())->items);
    }

    #[Test]
    public function eventsAreReadNewestFirstAndFiltered(): void
    {
        $ada = UserId::generate(new SeededRandomSource(1));
        $first = $this->append(1, AuditEventType::SignInFailed, '09:00', Actor::anonymous(), outcome: Outcome::Failure);
        $second = $this->append(2, AuditEventType::SignedIn, '10:00', Actor::person($ada), AuditTarget::user($ada));
        $machine = Actor::application(ClientId::fromString('m2m'));
        $third = $this->append(3, AuditEventType::ClientCreated, '11:00', $machine);

        $ids = fn (AuditQuery $query): array => array_map(
            static fn (AuditEvent $e): string => $e->id->value,
            $this->auditLog()->page($query, PageRequest::of())->items,
        );

        self::assertSame([$third->id->value, $second->id->value, $first->id->value], $ids(new AuditQuery()));
        self::assertSame([$second->id->value], $ids(new AuditQuery(actorUserId: $ada)));
        self::assertSame([$second->id->value], $ids(new AuditQuery(target: AuditTarget::user($ada))));
        self::assertSame([$third->id->value], $ids(new AuditQuery(clientId: ClientId::fromString('m2m'))));
        self::assertSame([$first->id->value], $ids(new AuditQuery(outcome: Outcome::Failure)));
        self::assertSame(
            [$second->id->value, $first->id->value],
            $ids(new AuditQuery(types: [AuditEventType::SignedIn, AuditEventType::SignInFailed])),
        );
        self::assertSame([$second->id->value], $ids(new AuditQuery(
            since: new DateTimeImmutable('2026-01-15T10:00:00Z'),
            until: new DateTimeImmutable('2026-01-15T11:00:00Z'),
        )));

        $page = $this->auditLog()->page(new AuditQuery(), PageRequest::of(2, 2));
        self::assertSame(3, $page->total);
        self::assertSame([$first->id->value], array_map(
            static fn (AuditEvent $e): string => $e->id->value,
            $page->items,
        ));
    }

    #[Test]
    public function aDirectoryIsReadBackAsItsProvisioningToken(): void
    {
        $token = ProvisioningTokenId::generate(new SeededRandomSource(7));
        $event = $this->append(1, AuditEventType::UserCreated, '09:00', Actor::provisioning($token));

        $stored = $this->auditLog()->find($event->id);

        self::assertSame(ActorKind::Provisioning, $stored?->actor->kind);
        self::assertTrue($stored?->actor->provisioningTokenId?->equals($token));
        self::assertNull($stored?->actor->userId);
        self::assertNull($stored?->actor->clientId);
    }

    #[Test]
    public function onlyWhatIsPastRetentionIsPurged(): void
    {
        $this->append(1, AuditEventType::SignedIn, '09:00', Actor::system());
        $kept = $this->append(2, AuditEventType::SignedIn, '10:00', Actor::system());

        self::assertSame(1, $this->auditLog()->purgeBefore(new DateTimeImmutable('2026-01-15T10:00:00Z')));
        self::assertSame(0, $this->auditLog()->purgeBefore(new DateTimeImmutable('2026-01-15T10:00:00Z')));
        self::assertEquals([$kept], $this->auditLog()->page(new AuditQuery(), PageRequest::of())->items);
    }

    private function append(
        int $seed,
        AuditEventType $type,
        string $time,
        Actor $actor,
        ?AuditTarget $target = null,
        Outcome $outcome = Outcome::Success,
    ): AuditEvent {
        $event = AuditEvent::record(
            AuditEventId::generate(new SeededRandomSource($seed)),
            $type,
            new DateTimeImmutable('2026-01-15T' . $time . ':00Z'),
            $actor,
            $target,
            $outcome,
        );
        $this->auditLog()->append($event);

        return $event;
    }
}
