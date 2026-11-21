<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Audit;

use Clavia\Adapter\Primary\Cli\PurgeAuditEventsCommand;
use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Audit\PurgeAuditEvents;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\ActorKind;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Audits;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAuditLog;
use ClaviaTest\Support\Fake\SeededRandomSource;
use LogicException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The recorder use cases write through, and the purge that is the trail's only deletion.
 */
final class AuditTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryAuditLog $log;
    private AuditContext $context;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->log = new InMemoryAuditLog();
        $this->context = new AuditContext();
    }

    public function testWithNobodyInTheContextTheSystemActs(): void
    {
        // The console, a scheduler: nothing set an actor, and nothing came over HTTP.
        Audits::into($this->log, $this->clock, $this->context)->record(AuditEventType::SigningKeyRotated);

        $event = $this->log->all()[0];
        self::assertSame(ActorKind::System, $event->actor->kind);
        self::assertNull($event->clientAddress);
        self::assertNull($event->userAgent);
        self::assertEquals($this->clock->now(), $event->occurredAt);
        self::assertSame(Outcome::Success, $event->outcome);
    }

    public function testTheContextNamesTheCallerAndWhereTheRequestCameFrom(): void
    {
        $operator = UserId::generate(new SeededRandomSource(3));
        $this->context->begin('198.51.100.4', 'Mozilla/5.0');
        $this->context->actAs(Actor::person($operator, ClientId::fromString('dashboard')));

        Audits::into($this->log, $this->clock, $this->context)
            ->record(AuditEventType::ClientDeleted, AuditTarget::client(ClientId::fromString('gone')));

        $event = $this->log->all()[0];
        self::assertSame(ActorKind::Person, $event->actor->kind);
        self::assertSame($operator->value, $event->actor->userId?->value);
        self::assertSame('dashboard', $event->actor->clientId?->value);
        self::assertSame('198.51.100.4', $event->clientAddress);
        self::assertSame('Mozilla/5.0', $event->userAgent);
        self::assertSame('gone', $event->target?->id);
    }

    public function testAnActorGivenOutrightOverridesTheContext(): void
    {
        // A sign-in is made by the person signing in, whoever the request was routed through.
        $this->context->actAs(Actor::system());

        Audits::into($this->log, $this->clock, $this->context)
            ->record(AuditEventType::SignedIn, actor: Actor::person(UserId::generate(new SeededRandomSource(4))));

        self::assertSame(ActorKind::Person, $this->log->all()[0]->actor->kind);
    }

    public function testARefusalIsRecordedAsAFailure(): void
    {
        Audits::into($this->log, $this->clock)->refused(
            AuditEventType::SignInFailed,
            details: ['reason' => 'throttled'],
            actor: Actor::anonymous(),
        );

        self::assertSame(Outcome::Failure, $this->log->ofType(AuditEventType::SignInFailed)[0]->outcome);
    }

    public function testDetailsTheEventRefusesAreABug(): void
    {
        // Detail names are written by this codebase: one that names a credential is a
        // mistake to fix, not a condition to handle.
        $this->expectException(LogicException::class);

        Audits::into($this->log, $this->clock)->record(AuditEventType::ClientUpdated, details: ['secret' => 'x']);
    }

    public function testThePurgeRemovesOnlyWhatIsPastRetention(): void
    {
        $audit = Audits::into($this->log, $this->clock);
        $audit->record(AuditEventType::UserCreated);
        $this->clock->advance(10 * 86_400);
        $audit->record(AuditEventType::UserUpdated);
        $this->clock->advance(25 * 86_400);

        $command = new CommandTester(new PurgeAuditEventsCommand(new PurgeAuditEvents($this->log, $this->clock, 30)));

        self::assertSame(0, $command->execute([]));
        self::assertStringContainsString('Removed 1 audit event past retention.', $command->getDisplay());
        self::assertCount(1, $this->log->ofType(AuditEventType::UserUpdated));
        self::assertSame([], $this->log->ofType(AuditEventType::UserCreated));

        $command->execute([]);
        self::assertStringContainsString('No audit event is past retention.', $command->getDisplay());
    }
}
