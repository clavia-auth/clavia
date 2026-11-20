<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Mfa;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\FactorAlreadyConfirmed;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

final class MfaFactorTest extends TestCase
{
    private TotpSecret $secret;
    private DateTimeImmutable $now;
    private MfaFactor $factor;

    #[\Override]
    protected function setUp(): void
    {
        $this->secret = TotpSecret::generate(new SeededRandomSource(1));
        $this->now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->factor = MfaFactor::stage(UserId::generate(new SeededRandomSource(2)), 'sealed', $this->now);
    }

    public function testAnAcceptedCodeRecordsItsStepAndCannotBeAcceptedAgain(): void
    {
        $code = Totp::codeAt($this->secret, $this->now);

        self::assertTrue($this->factor->accept($this->secret, $code, $this->now));
        self::assertSame(Totp::timeStep($this->now), $this->factor->lastUsedStep);
        self::assertFalse($this->factor->accept($this->secret, $code, $this->now));
    }

    public function testACodeTypedWithSpacesIsTheSameCode(): void
    {
        $code = Totp::codeAt($this->secret, $this->now);

        $typed = ' ' . substr($code, 0, 3) . ' ' . substr($code, 3) . "\t";

        self::assertTrue($this->factor->accept($this->secret, $typed, $this->now));
    }

    public function testAWrongCodeChangesNothing(): void
    {
        self::assertFalse($this->factor->accept($this->secret, '', $this->now));
        self::assertNull($this->factor->lastUsedStep);
    }

    public function testAFactorIsConfirmedOnlyOnceACodeFromItWasAccepted(): void
    {
        try {
            $this->factor->confirm($this->now);
            self::fail('A factor nobody proved holding was confirmed.');
        } catch (LogicException) {
            self::assertFalse($this->factor->isConfirmed());
        }

        self::assertTrue($this->acceptCurrentCode());
        $this->factor->confirm($this->now);

        self::assertTrue($this->factor->isConfirmed());
        self::assertSame($this->now, $this->factor->confirmedAt);
        $this->expectException(LogicException::class);
        $this->factor->confirm($this->now);
    }

    public function testRestagingReplacesTheSeedAndForgetsTheStepUntilConfirmed(): void
    {
        self::assertTrue($this->acceptCurrentCode());

        $this->factor->restage('sealed-again');

        self::assertSame('sealed-again', $this->factor->sealedSecret);
        self::assertNull($this->factor->lastUsedStep);

        self::assertTrue($this->acceptCurrentCode());
        $this->factor->confirm($this->now);
        $this->expectException(FactorAlreadyConfirmed::class);
        $this->factor->restage('a-third-seed');
    }

    public function testRecoveryCodesAreDistinctAndWrittenInTheirAlphabet(): void
    {
        $codes = RecoveryCode::issue(new SeededRandomSource(3), 20);

        self::assertCount(20, $codes);
        self::assertCount(20, array_unique($codes));
        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^([a-hjkmnp-z2-9]{4}-){2}[a-hjkmnp-z2-9]{4}$/D', $code);
        }
        self::assertNotSame($codes, RecoveryCode::issue(new SeededRandomSource(4), 20));
    }

    public function testARecoveryCodeIsLookedUpHoweverItWasTyped(): void
    {
        $digest = RecoveryCode::digest('abcd-efgh-jkmn');

        self::assertTrue($digest->equals(RecoveryCode::digest('ABCD-EFGH-JKMN')));
        self::assertTrue($digest->equals(RecoveryCode::digest(' abcdefghjkmn ')));
        self::assertTrue($digest->equals(RecoveryCode::digest('abcd efgh jkmn')));
        self::assertFalse($digest->equals(RecoveryCode::digest('abcd-efgh-jkmp')));
    }

    public function testTheMethodsOfASecondStepAddToTheFirstWithoutRepeating(): void
    {
        self::assertSame(
            [
                AuthenticationMethod::Password,
                AuthenticationMethod::OneTimePassword,
                AuthenticationMethod::MultipleFactors,
            ],
            AuthenticationMethod::combined([AuthenticationMethod::Password], [AuthenticationMethod::OneTimePassword]),
        );
        self::assertSame(
            [AuthenticationMethod::Password, AuthenticationMethod::MultipleFactors],
            AuthenticationMethod::combined([AuthenticationMethod::Password], [AuthenticationMethod::MultipleFactors]),
        );
        self::assertSame(['pwd', 'otp', 'mfa'], array_map(
            static fn (AuthenticationMethod $method): string => $method->value,
            AuthenticationMethod::combined([AuthenticationMethod::Password], [AuthenticationMethod::OneTimePassword]),
        ));
    }

    private function acceptCurrentCode(): bool
    {
        return $this->factor->accept($this->secret, Totp::codeAt($this->secret, $this->now), $this->now);
    }
}
