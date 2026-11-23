<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class SessionTest extends TestCase
{
    private const int WEEK = 604800;
    private const int EIGHT_HOURS = 28800;

    public function testASessionEndsItsAbsoluteLifetimeAfterTheSignIn(): void
    {
        $session = $this->establish('2026-01-15T10:00:00.250000Z');

        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00.250000Z'), $session->authenticatedAt);
        self::assertEquals(new DateTimeImmutable('2026-01-22T10:00:00.250000Z'), $session->expiresAt);
        self::assertSame([AuthenticationMethod::Password], $session->methods);
        self::assertSame('the-sid', $session->sid);
    }

    public function testItIsExpiredFromItsCeilingOnwards(): void
    {
        $session = $this->establish('2026-01-15T10:00:00Z');

        self::assertFalse($session->isExpiredAt(new DateTimeImmutable('2026-01-22T09:59:59Z')));
        self::assertTrue($session->isExpiredAt(new DateTimeImmutable('2026-01-22T10:00:00Z')));
    }

    public function testTheIdleWindowIsTheIdleLifetimeWhileTheCeilingIsFarAway(): void
    {
        $session = $this->establish('2026-01-15T10:00:00Z');

        $window = $session->idleWindowAt(new DateTimeImmutable('2026-01-16T10:00:00Z'), self::EIGHT_HOURS);

        self::assertSame(self::EIGHT_HOURS, $window);
    }

    public function testTheIdleWindowNeverReachesPastTheCeiling(): void
    {
        $session = $this->establish('2026-01-15T10:00:00Z');

        $windowAt = static fn (string $at): int
            => $session->idleWindowAt(new DateTimeImmutable($at), self::EIGHT_HOURS);

        self::assertSame(3600, $windowAt('2026-01-22T09:00:00Z'));
        self::assertSame(1, $windowAt('2026-01-22T09:59:59Z'));
        // Past the ceiling the smallest expressible window: the caller ends such a session.
        self::assertSame(1, $windowAt('2026-02-01T00:00:00Z'));
    }

    public function testAMethodRecordedTwiceIsRecordedOnce(): void
    {
        $session = Session::establish(
            UserId::generate(new SeededRandomSource(1)),
            [AuthenticationMethod::Password, AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            self::WEEK,
        );

        self::assertSame([AuthenticationMethod::Password], $session->methods);
    }

    public function testASessionWithoutAMethodIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        Session::establish(
            UserId::generate(new SeededRandomSource(1)),
            [],
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            self::WEEK,
        );
    }

    public function testASessionWithoutASidIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        Session::reconstitute(
            UserId::generate(new SeededRandomSource(1)),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            new DateTimeImmutable('2026-01-22T10:00:00Z'),
            [AuthenticationMethod::Password],
            '',
            ConnectionName::defaultPool(),
        );
    }

    public function testASessionCannotEndBeforeItBegins(): void
    {
        $this->expectException(InvalidValue::class);

        Session::reconstitute(
            UserId::generate(new SeededRandomSource(1)),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            [AuthenticationMethod::Password],
            'the-sid',
            ConnectionName::defaultPool(),
        );
    }

    public function testTheMethodsAreTheRegisteredReferences(): void
    {
        // RFC 8176 §2: what relying parties look for in the `amr` claim.
        self::assertSame('pwd', AuthenticationMethod::Password->value);
    }

    private function establish(string $at): Session
    {
        return Session::establish(
            UserId::generate(new SeededRandomSource(1)),
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable($at),
            self::WEEK,
        );
    }

    public function testASteppedUpSessionKeepsWhatItIsAndMovesOnlyWhenAndHow(): void
    {
        $session = Session::reconstitute(
            UserId::fromString('0190a4f2-7c1e-4b3a-9c2d-5e6f7a8b9c0d'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            new DateTimeImmutable('2026-01-15T18:00:00Z'),
            [AuthenticationMethod::Password],
            'the-sid',
            ConnectionName::defaultPool(),
            [ClientId::fromString('spa')],
        );

        $raised = $session->steppedUp(
            [AuthenticationMethod::OneTimePassword],
            new DateTimeImmutable('2026-01-15T12:00:00Z'),
        );

        self::assertSame(
            [
                AuthenticationMethod::Password,
                AuthenticationMethod::OneTimePassword,
                AuthenticationMethod::MultipleFactors,
            ],
            $raised->methods,
        );
        self::assertEquals(new DateTimeImmutable('2026-01-15T12:00:00Z'), $raised->authenticatedAt);
        // Never a longer life, never another session to the applications signed in through it.
        self::assertEquals($session->expiresAt, $raised->expiresAt);
        self::assertSame('the-sid', $raised->sid);
        self::assertEquals($session->clients, $raised->clients);
        self::assertTrue($raised->connection->equals($session->connection));
    }
}
