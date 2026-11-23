<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\Sessions;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class SessionsTest extends TestCase
{
    private const int IDLE = 3600;
    private const int ABSOLUTE = 86400;

    private FrozenClock $clock;
    private InMemorySessionStore $store;
    private Sessions $sessions;
    private UserId $userId;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->store = new InMemorySessionStore($this->clock);
        $this->sessions = new Sessions(
            $this->store,
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            self::IDLE,
            self::ABSOLUTE,
            new InMemoryDomainEvents(),
        );
        $this->userId = UserId::generate(new SeededRandomSource(2));
    }

    public function testAnEstablishedSessionIsFoundByTheIdentifierItWasHandedOutWith(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $session = $this->sessions->resolve($sessionId);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $sessionId);
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($this->userId));
        self::assertEquals($this->clock->now(), $session->authenticatedAt);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $session->sid);
        self::assertNotSame($sessionId, $session->sid);
        self::assertSame(self::IDLE, $this->store->ttl($sessionId));
    }

    public function testEstablishingEndsTheSessionTheBrowserHeld(): void
    {
        $first = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $second = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            $first,
        );

        self::assertNotSame($first, $second);
        self::assertNull($this->sessions->resolve($first));
        self::assertNotNull($this->sessions->resolve($second));
        self::assertSame(1, $this->store->count());
    }

    public function testEachSessionHasItsOwnSid(): void
    {
        $establish = fn (): string => $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $first = $this->sessions->resolve($establish());
        $second = $this->sessions->resolve($establish());

        self::assertNotSame($first?->sid, $second?->sid);
    }

    public function testUsingASessionStartsItsIdleWindowOver(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $this->clock->advance(self::IDLE - 1);
        self::assertNotNull($this->sessions->resolve($sessionId));
        $this->clock->advance(self::IDLE - 1);

        self::assertNotNull($this->sessions->resolve($sessionId));
    }

    public function testASessionLeftIdleTooLongIsGone(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $this->clock->advance(self::IDLE);

        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testUseNeverCarriesASessionPastItsAbsoluteLifetime(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        for ($elapsed = 0; $elapsed < self::ABSOLUTE - self::IDLE; $elapsed += 1800) {
            $this->clock->advance(1800);
            self::assertNotNull($this->sessions->resolve($sessionId));
        }

        // Half an hour before the ceiling the renewal is cut short to it, not a full window.
        $this->clock->advance(1800);
        self::assertNotNull($this->sessions->resolve($sessionId));
        self::assertSame(1800, $this->store->ttl($sessionId));
        $this->clock->advance(1800);

        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testASessionFoundPastItsCeilingIsDeletedRatherThanRenewed(): void
    {
        // A store that outlived the ceiling — a clock change, a restored dump.
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $session = $this->store->find($sessionId);
        self::assertNotNull($session);
        $this->store->save($sessionId, $session, 10 * self::ABSOLUTE);

        $this->clock->advance(self::ABSOLUTE);

        self::assertNull($this->sessions->resolve($sessionId));
        self::assertNull($this->store->find($sessionId));
    }

    public function testEndingASessionReturnsWhatItWas(): void
    {
        $sessionId = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $ended = $this->sessions->end($sessionId);

        self::assertTrue($ended?->userId->equals($this->userId));
        self::assertNull($this->sessions->resolve($sessionId));
    }

    public function testNothingToResolveOrEndIsNotAnError(): void
    {
        self::assertNull($this->sessions->resolve(null));
        self::assertNull($this->sessions->resolve(''));
        self::assertNull($this->sessions->resolve('never-issued'));
        self::assertNull($this->sessions->end(null));
        self::assertNull($this->sessions->end(''));
        self::assertNull($this->sessions->end('never-issued'));
    }

    public function testAStepUpKeepsTheApplicationsSignedInThroughTheSession(): void
    {
        // Back-channel logout reaches them by the sid, which a step-up keeps.
        $id = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $session = $this->sessions->resolve($id);
        self::assertNotNull($session);
        $this->sessions->recordClient($session, ClientId::fromString('spa'));

        $raised = $this->sessions->stepUp($id, $session->sid, [AuthenticationMethod::OneTimePassword]);

        self::assertNotNull($raised);
        self::assertNull($this->sessions->resolve($id), 'The old identifier opens nothing.');
        $after = $this->sessions->resolve($raised);
        self::assertNotNull($after);
        self::assertSame($session->sid, $after->sid);
        self::assertSame(['spa'], array_map(static fn (ClientId $client): string => $client->value, $after->clients));
    }

    public function testAStepUpNeedsTheSessionItWasOpenedFor(): void
    {
        $id = $this->sessions->establish(
            $this->userId,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        self::assertNull($this->sessions->stepUp($id, 'another-sid', [AuthenticationMethod::OneTimePassword]));
        self::assertNull($this->sessions->stepUp(null, 'another-sid', [AuthenticationMethod::OneTimePassword]));
        self::assertSame(
            [AuthenticationMethod::Password],
            $this->sessions->resolve($id)?->methods,
            'A refused step-up changes nothing.',
        );
    }
}
