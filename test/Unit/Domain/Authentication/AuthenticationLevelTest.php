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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The level each way of signing in reaches (docs/design/mfa-policies.md §3).
 */
final class AuthenticationLevelTest extends TestCase
{
    /**
     * Every `amr` the sign-in flows record, and the level it is.
     *
     * @return iterable<string, array{list<M>, AuthenticationLevel|null}>
     */
    public static function signIns(): iterable
    {
        yield 'a password' => [[M::Password], null];
        yield 'an external provider' => [[M::External], null];
        yield 'an emailed code' => [[M::OneTimePassword], null];
        yield 'nothing witnessed' => [[], null];
        yield 'a password and an app' => [
            [M::Password, M::OneTimePassword, M::MultipleFactors],
            AuthenticationLevel::Mfa,
        ];
        yield 'a provider and an app' => [
            [M::External, M::OneTimePassword, M::MultipleFactors],
            AuthenticationLevel::Mfa,
        ];
        yield 'a password and a synced passkey' => [
            [M::Password, M::SoftwareKey, M::MultipleFactors],
            AuthenticationLevel::PhishingResistant,
        ];
        yield 'a password and a security key, presence only' => [
            [M::Password, M::HardwareKey, M::UserPresence, M::MultipleFactors],
            // Device-bound by its own account only: no attestation, so no `phrh`.
            AuthenticationLevel::PhishingResistant,
        ];
        yield 'a verified synced passkey alone' => [
            [M::SoftwareKey, M::MultipleFactors],
            AuthenticationLevel::PhishingResistant,
        ];
        yield 'a verified security key alone' => [
            [M::HardwareKey, M::MultipleFactors],
            AuthenticationLevel::PhishingResistant,
        ];
        // A passkey that did not satisfy MFA (CLAVIA_PASSKEY_SATISFIES_MFA off) is one factor.
        yield 'a passkey that was not enough on its own' => [[M::SoftwareKey], null];
    }

    /**
     * @param list<M> $methods
     */
    #[DataProvider('signIns')]
    public function testEachSignInReachesItsLevel(array $methods, ?AuthenticationLevel $expected): void
    {
        self::assertSame($expected, AuthenticationLevel::of($methods));
    }

    public function testPhishingResistantMeetsMfaAndNotTheReverse(): void
    {
        self::assertTrue(AuthenticationLevel::PhishingResistant->meets(AuthenticationLevel::Mfa));
        self::assertTrue(AuthenticationLevel::PhishingResistant->meets(AuthenticationLevel::PhishingResistant));
        self::assertFalse(AuthenticationLevel::Mfa->meets(AuthenticationLevel::PhishingResistant));
    }

    public function testTheValuesAreTheRegisteredOnesWeakestFirst(): void
    {
        self::assertSame(
            ['http://schemas.openid.net/pape/policies/2007/06/multi-factor', 'phr'],
            AuthenticationLevel::supportedAcrValues(),
        );
    }
}
