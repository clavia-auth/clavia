<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\Redemption;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AuthorizationCodeTest extends TestCase
{
    private const string ISSUED_AT = '2026-01-15T10:00:00Z';

    public function testItExpiresWhenItsLifetimeIsOver(): void
    {
        $code = $this->issue();

        self::assertEquals(new DateTimeImmutable('2026-01-15T10:01:00Z'), $code->expiresAt);
        self::assertEquals(new DateTimeImmutable(self::ISSUED_AT), $code->createdAt);
        self::assertNull($code->usedAt());
    }

    public function testALiveCodeIsSpentByTheClientItWasIssuedTo(): void
    {
        $code = $this->issue();
        $now = new DateTimeImmutable('2026-01-15T10:00:30Z');

        self::assertSame(Redemption::Redeemed, $code->redeem(ClientId::fromString('spa'), $now));
        self::assertSame($now, $code->usedAt());
    }

    public function testASecondRedemptionIsAReplay(): void
    {
        $code = $this->issue();
        $first = new DateTimeImmutable('2026-01-15T10:00:30Z');
        self::assertSame(Redemption::Redeemed, $code->redeem(ClientId::fromString('spa'), $first));

        $outcome = $code->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:00:31Z'));

        self::assertSame(Redemption::Replayed, $outcome);
        self::assertSame($first, $code->usedAt());
    }

    public function testAnotherClientLearnsNothingAndChangesNothing(): void
    {
        $code = $this->issue();

        $outcome = $code->redeem(ClientId::fromString('other'), new DateTimeImmutable('2026-01-15T10:00:30Z'));

        self::assertSame(Redemption::IssuedToAnotherClient, $outcome);
        self::assertNull($code->usedAt());
    }

    public function testAnotherClientIsNotToldThatACodeWasAlreadySpent(): void
    {
        $code = $this->issue();
        self::assertSame(
            Redemption::Redeemed,
            $code->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:00:30Z')),
        );

        $outcome = $code->redeem(ClientId::fromString('other'), new DateTimeImmutable('2026-01-15T10:00:31Z'));

        // Not `Replayed`: a stranger presenting someone else's code must not be able to
        // trigger the revocation of that client's tokens.
        self::assertSame(Redemption::IssuedToAnotherClient, $outcome);
    }

    public function testAnExpiredCodeIsRefusedWithoutBeingSpent(): void
    {
        $code = $this->issue();

        $outcome = $code->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:01:01Z'));

        self::assertSame(Redemption::Expired, $outcome);
        self::assertNull($code->usedAt());
    }

    public function testTheInstantOfExpiryIsAlreadyTooLate(): void
    {
        $lastMoment = $this->issue();
        $tooLate = $this->issue();

        self::assertSame(
            Redemption::Redeemed,
            $lastMoment->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:00:59.999999Z')),
        );
        self::assertSame(
            Redemption::Expired,
            $tooLate->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:01:00Z')),
        );
    }

    public function testASpentCodePresentedAfterExpiryIsStillAReplay(): void
    {
        $code = $this->issue();
        self::assertSame(
            Redemption::Redeemed,
            $code->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T10:00:30Z')),
        );

        $outcome = $code->redeem(ClientId::fromString('spa'), new DateTimeImmutable('2026-01-15T12:00:00Z'));

        self::assertSame(Redemption::Replayed, $outcome);
    }

    public function testACodeIsBoundByAChallengeOrANonceAndNeverByNeither(): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessageIsOrContains('bound to its client by a nonce instead');

        AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(1)),
            Digest::of('the-code'),
            ClientId::fromString('backend'),
            UserId::generate(new SeededRandomSource(2)),
            'https://app.example/cb',
            ScopeSet::fromString('openid'),
            null,
            null,
            null,
            AuthenticationContext::unknown(),
            new DateTimeImmutable(self::ISSUED_AT),
            60,
        );
    }

    private function issue(): AuthorizationCode
    {
        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(1)),
            Digest::of('the-code'),
            ClientId::fromString('spa'),
            UserId::generate(new SeededRandomSource(2)),
            'https://app.example/cb',
            ScopeSet::fromString('openid'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            null,
            AuthenticationContext::unknown(),
            new DateTimeImmutable(self::ISSUED_AT),
            60,
        );
    }
}
