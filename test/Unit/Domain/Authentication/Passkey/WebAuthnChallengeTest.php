<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * A ceremony's challenge: random, short-lived, and bound to what it is for (WebAuthn Level 3
 * §13.4.3).
 */
final class WebAuthnChallengeTest extends TestCase
{
    private DateTimeImmutable $now;

    private UserId $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->user = UserId::generate(new SeededRandomSource(2));
    }

    public function testAChallengeIsThirtyTwoRandomBytesAndTravelsAsBase64Url(): void
    {
        $random = new SeededRandomSource(1);

        $first = WebAuthnChallenge::forRegistration($random, $this->user, $this->now, 300);
        $second = WebAuthnChallenge::forRegistration($random, $this->user, $this->now, 300);

        self::assertSame(32, strlen($first->challenge));
        self::assertNotSame($first->challenge, $second->challenge);
        self::assertSame(rtrim(strtr(base64_encode($first->challenge), '+/', '-_'), '='), $first->toBase64Url());
    }

    public function testARegistrationIsBoundToItsAccountAndNothingElse(): void
    {
        $challenge = WebAuthnChallenge::forRegistration(new SeededRandomSource(1), $this->user, $this->now, 300);

        self::assertSame(WebAuthnPurpose::Registration, $challenge->purpose);
        self::assertTrue($challenge->userId?->equals($this->user));
        self::assertNull($challenge->context);
        self::assertTrue($challenge->isFor(WebAuthnPurpose::Registration));
        self::assertFalse($challenge->isFor(WebAuthnPurpose::Registration, 'anything'));
    }

    public function testASignInIsBoundToItsLoginStateByDigestAndKnowsNoAccount(): void
    {
        $challenge = WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'login-state', $this->now, 300);

        self::assertSame(WebAuthnPurpose::SignIn, $challenge->purpose);
        self::assertNull($challenge->userId);
        self::assertTrue($challenge->context?->equals(Digest::of('login-state')));
        self::assertTrue($challenge->isFor(WebAuthnPurpose::SignIn, 'login-state'));
        self::assertFalse($challenge->isFor(WebAuthnPurpose::SignIn, 'another-state'));
        self::assertFalse($challenge->isFor(WebAuthnPurpose::SignIn));
    }

    public function testASecondFactorIsBoundToItsAccountAndItsMfaChallenge(): void
    {
        $challenge = WebAuthnChallenge::forSecondFactor(
            new SeededRandomSource(1),
            $this->user,
            'mfa-handle',
            $this->now,
            300,
        );

        self::assertSame(WebAuthnPurpose::SecondFactor, $challenge->purpose);
        self::assertTrue($challenge->userId?->equals($this->user));
        self::assertTrue($challenge->isFor(WebAuthnPurpose::SecondFactor, 'mfa-handle'));
        self::assertFalse($challenge->isFor(WebAuthnPurpose::SecondFactor, 'login-state'));
    }

    public function testAChallengeMadeForOnePurposeIsNotForAnother(): void
    {
        $signIn = WebAuthnChallenge::forSignIn(new SeededRandomSource(1), 'same-handle', $this->now, 300);

        self::assertFalse($signIn->isFor(WebAuthnPurpose::SecondFactor, 'same-handle'));
        self::assertFalse($signIn->isFor(WebAuthnPurpose::Registration, 'same-handle'));
    }

    public function testItExpiresAtItsLifetimeExactly(): void
    {
        $challenge = WebAuthnChallenge::forRegistration(new SeededRandomSource(1), $this->user, $this->now, 300);

        self::assertFalse($challenge->isExpired($this->now));
        self::assertFalse($challenge->isExpired($this->now->modify('+299 seconds')));
        self::assertTrue($challenge->isExpired($this->now->modify('+300 seconds')));
        self::assertTrue($challenge->isExpired($this->now->modify('+1 day')));
    }

    public function testACeremonyLivesAtLeastASecond(): void
    {
        $this->expectException(InvalidValue::class);

        WebAuthnChallenge::forRegistration(new SeededRandomSource(1), $this->user, $this->now, 0);
    }

    public function testWhatIsReadBackMustStillBeAChallengeOfItsPurpose(): void
    {
        $bytes = str_repeat("\x05", 32);
        $context = Digest::of('handle');

        $ok = [
            WebAuthnChallenge::reconstitute($bytes, WebAuthnPurpose::Registration, $this->user, null, $this->now),
            WebAuthnChallenge::reconstitute($bytes, WebAuthnPurpose::SignIn, null, $context, $this->now),
            WebAuthnChallenge::reconstitute($bytes, WebAuthnPurpose::SecondFactor, $this->user, $context, $this->now),
        ];
        self::assertCount(3, $ok);

        $bad = [
            'a short challenge' => [str_repeat("\x05", 31), WebAuthnPurpose::Registration, $this->user, null],
            'a registration without an account' => [$bytes, WebAuthnPurpose::Registration, null, null],
            'a registration with a context' => [$bytes, WebAuthnPurpose::Registration, $this->user, $context],
            'a sign-in naming an account' => [$bytes, WebAuthnPurpose::SignIn, $this->user, $context],
            'a sign-in without a context' => [$bytes, WebAuthnPurpose::SignIn, null, null],
            'a second factor without an account' => [$bytes, WebAuthnPurpose::SecondFactor, null, $context],
            'a second factor without a context' => [$bytes, WebAuthnPurpose::SecondFactor, $this->user, null],
        ];
        foreach ($bad as $name => [$challenge, $purpose, $user, $ctx]) {
            try {
                WebAuthnChallenge::reconstitute($challenge, $purpose, $user, $ctx, $this->now);
                self::fail($name . ' was accepted.');
            } catch (InvalidValue $refused) {
                self::assertNotSame('', $refused->getMessage(), $name);
            }
        }
    }

    public function testOnlyASignInLeavesTheAccountToTheResponseAndOnlyASecondFactorSettlesForPresence(): void
    {
        self::assertFalse(WebAuthnPurpose::SignIn->identifiesTheAccountFirst());
        self::assertTrue(WebAuthnPurpose::SecondFactor->identifiesTheAccountFirst());
        self::assertTrue(WebAuthnPurpose::Registration->identifiesTheAccountFirst());
        self::assertTrue(WebAuthnPurpose::SignIn->requiresUserVerification());
        self::assertTrue(WebAuthnPurpose::Registration->requiresUserVerification());
        self::assertFalse(WebAuthnPurpose::SecondFactor->requiresUserVerification());
    }
}
