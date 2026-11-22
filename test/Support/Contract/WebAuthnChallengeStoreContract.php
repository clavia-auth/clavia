<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see WebAuthnChallengeStore} must do. Expiry is asserted by each implementation's
 * own test.
 */
trait WebAuthnChallengeStoreContract
{
    abstract protected function ceremonies(): WebAuthnChallengeStore;

    #[Test]
    public function aRegistrationIsReadBackWhole(): void
    {
        $challenge = WebAuthnChallenge::forRegistration(
            new SeededRandomSource(1),
            UserId::generate(new SeededRandomSource(2)),
            new DateTimeImmutable('2026-01-15T10:00:00.123456Z'),
            300,
        );
        $this->ceremonies()->open('handle-1', $challenge, 300);

        $claimed = $this->ceremonies()->claim('handle-1');

        self::assertNotNull($claimed);
        self::assertSame($challenge->challenge, $claimed->challenge);
        self::assertSame(WebAuthnPurpose::Registration, $claimed->purpose);
        self::assertTrue($claimed->userId?->equals($challenge->userId ?? throw new \LogicException()));
        self::assertNull($claimed->context);
        self::assertSame('2026-01-15T10:05:00.123456+00:00', $claimed->expiresAt->format('Y-m-d\\TH:i:s.uP'));
    }

    #[Test]
    public function aSignInIsBoundToItsLoginStateByDigestAndNamesNoAccount(): void
    {
        $challenge = WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'login-state', $this->now(), 300);
        $this->ceremonies()->open('handle-1', $challenge, 300);

        $claimed = $this->ceremonies()->claim('handle-1');

        self::assertNotNull($claimed);
        self::assertSame(WebAuthnPurpose::SignIn, $claimed->purpose);
        self::assertNull($claimed->userId);
        self::assertTrue($claimed->context?->equals(Digest::of('login-state')));
        self::assertTrue($claimed->isFor(WebAuthnPurpose::SignIn, 'login-state'));
        self::assertFalse($claimed->isFor(WebAuthnPurpose::SignIn, 'another'));
    }

    #[Test]
    public function aSecondFactorIsBoundToItsAccountAndItsChallenge(): void
    {
        $user = UserId::generate(new SeededRandomSource(2));
        $this->ceremonies()->open(
            'handle-1',
            WebAuthnChallenge::forSecondFactor(new SeededRandomSource(1), $user, 'mfa-handle', $this->now(), 300),
            300,
        );

        $claimed = $this->ceremonies()->claim('handle-1');

        self::assertNotNull($claimed);
        self::assertSame(WebAuthnPurpose::SecondFactor, $claimed->purpose);
        self::assertTrue($claimed->userId?->equals($user));
        self::assertTrue($claimed->isFor(WebAuthnPurpose::SecondFactor, 'mfa-handle'));
    }

    #[Test]
    public function aCeremonyIsClaimedOnceAndOnlyOnce(): void
    {
        $this->ceremonies()->open(
            'handle-1',
            WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'login-state', $this->now(), 300),
            300,
        );

        self::assertNotNull($this->ceremonies()->claim('handle-1'));
        self::assertNull($this->ceremonies()->claim('handle-1'));
    }

    #[Test]
    public function aHandleThatWasNeverOpenedOrIsEmptyClaimsNothing(): void
    {
        self::assertNull($this->ceremonies()->claim('never-opened'));
        self::assertNull($this->ceremonies()->claim(''));
    }

    #[Test]
    public function aHandleIsMatchedExactly(): void
    {
        $this->ceremonies()->open(
            'handle-1',
            WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'login-state', $this->now(), 300),
            300,
        );

        self::assertNull($this->ceremonies()->claim('Handle-1'));
        self::assertNull($this->ceremonies()->claim('handle-1 '));
        self::assertNotNull($this->ceremonies()->claim('handle-1'));
    }

    private function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T10:00:00Z');
    }
}
