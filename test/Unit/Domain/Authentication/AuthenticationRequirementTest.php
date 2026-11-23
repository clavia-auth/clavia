<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication;

use Clavia\Domain\Authentication\AuthenticationLevel;
use Clavia\Domain\Authentication\AuthenticationMethod as M;
use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * `acr_values` as a requirement (docs/design/mfa-policies.md §2), and the step-up challenge
 * that answers it (§5.2).
 */
final class AuthenticationRequirementTest extends TestCase
{
    private const string MFA = 'http://schemas.openid.net/pape/policies/2007/06/multi-factor';

    public function testKnownValuesAreKeptInOrderAndUnknownOnesIgnored(): void
    {
        $requirement = AuthenticationRequirement::fromAcrValues('phr urn:other:gold ' . self::MFA . ' phr');

        self::assertSame(['phr', self::MFA], $requirement->acrValues());
        self::assertTrue(AuthenticationRequirement::fromAcrValues('urn:other:gold')->isEmpty());
        self::assertTrue(AuthenticationRequirement::fromAcrValues(null)->isEmpty());
    }

    public function testAParameterNamingNothingIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        AuthenticationRequirement::fromAcrValues('   ');
    }

    public function testAnyAcceptedLevelMeetsIt(): void
    {
        $either = AuthenticationRequirement::fromAcrValues('phr ' . self::MFA);
        $phr = AuthenticationRequirement::fromAcrValues('phr');

        self::assertTrue($either->isMetBy([M::Password, M::OneTimePassword, M::MultipleFactors]));
        self::assertFalse($phr->isMetBy([M::Password, M::OneTimePassword, M::MultipleFactors]));
        self::assertTrue($phr->isMetBy([M::Password, M::SoftwareKey, M::MultipleFactors]));
        self::assertFalse($either->isMetBy([M::Password]));
        self::assertTrue(AuthenticationRequirement::none()->isMetBy([M::Password]));
    }

    public function testAPolicyPutsAFloorUnderTheRequestNeverLowersIt(): void
    {
        $mfa = AuthenticationLevel::Mfa;

        // Nothing asked: the policy is the requirement.
        self::assertSame([self::MFA], AuthenticationRequirement::none()->withMinimum($mfa)->acrValues());
        // `phr` asked meets MFA: it stays, alone.
        self::assertSame(['phr'], AuthenticationRequirement::fromAcrValues('phr')->withMinimum($mfa)->acrValues());
        // No policy: nothing changes.
        self::assertTrue(AuthenticationRequirement::none()->withMinimum(MfaPolicy::Optional->level())->isEmpty());
        self::assertSame(AuthenticationLevel::Mfa, MfaPolicy::Required->level());
    }

    public function testAnAuthenticatorAppIsAcceptedOnlyWhereMfaIsEnough(): void
    {
        self::assertTrue(AuthenticationRequirement::fromAcrValues(self::MFA)->accepts(AuthenticationLevel::Mfa));
        self::assertTrue(AuthenticationRequirement::none()->accepts(AuthenticationLevel::Mfa));
        self::assertFalse(AuthenticationRequirement::fromAcrValues('phr')->accepts(AuthenticationLevel::Mfa));
    }

    public function testAPolicyIsReadOnlyFromItsTwoValues(): void
    {
        self::assertSame(MfaPolicy::Required, MfaPolicy::fromString('required'));
        $this->expectException(InvalidValue::class);
        MfaPolicy::fromString('Required');
    }

    public function testAStepUpTakesOnlyAFactorThatIsEnough(): void
    {
        $session = $this->session([M::Password]);
        $mfa = MfaChallenge::stepUp($session, AuthenticationRequirement::fromAcrValues(self::MFA), '/next', null);
        $phr = MfaChallenge::stepUp($session, AuthenticationRequirement::fromAcrValues('phr'), '/next', null);

        self::assertTrue($mfa->isStepUp());
        self::assertSame($session->sid, $mfa->stepUpOf);
        self::assertTrue($mfa->isAnsweredBy([M::OneTimePassword]));
        self::assertTrue($mfa->isAnsweredBy([]), 'A recovery code is a second factor.');
        // An app's code cannot make a password phishing-resistant; a passkey can.
        self::assertFalse($phr->isAnsweredBy([M::OneTimePassword]));
        self::assertFalse($phr->isAnsweredBy([]));
        self::assertTrue($phr->isAnsweredBy([M::SoftwareKey]));
    }

    public function testAPasskeyThatWasNotEnoughOnItsOwnIsRaisedByAnApp(): void
    {
        // With CLAVIA_PASSKEY_SATISFIES_MFA off, a passkey sign-in is one factor; an app's code
        // then makes it multi-factor with a passkey in it: `phr`.
        $challenge = MfaChallenge::stepUp(
            $this->session([M::SoftwareKey]),
            AuthenticationRequirement::fromAcrValues('phr'),
            '/next',
            null,
        );

        self::assertTrue($challenge->isAnsweredBy([M::OneTimePassword]));
    }

    /**
     * @param list<M> $methods
     */
    private function session(array $methods): Session
    {
        return Session::establish(
            UserId::fromString('0190a4f2-7c1e-4b3a-9c2d-5e6f7a8b9c0d'),
            $methods,
            ConnectionName::defaultPool(),
            'the-sid',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
        );
    }
}
