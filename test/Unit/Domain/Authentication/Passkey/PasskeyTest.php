<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication\Passkey;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CounterRegressed;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * The rules a passkey keeps: a counter that grows (or never moves, for a synced passkey), a
 * backup state that cannot contradict its eligibility, and how a sign-in with it is reported.
 *
 * WebAuthn Level 3 §6.1.3 (the signature counter, backup eligibility and state) and RFC 8176 §2
 * (`hwk`, `swk`, `user`).
 */
final class PasskeyTest extends TestCase
{
    private DateTimeImmutable $now;

    #[\Override]
    protected function setUp(): void
    {
        $this->now = new DateTimeImmutable('2026-01-15T10:00:00Z');
    }

    public function testARegisteredPasskeyIsUnusedAndKeepsWhatItWasGiven(): void
    {
        $passkey = $this->passkey(signCount: 3, transports: [Transport::Usb, Transport::Nfc, Transport::Usb]);

        self::assertSame(3, $passkey->signCount);
        self::assertSame([Transport::Usb, Transport::Nfc], $passkey->transports, 'No transport twice.');
        self::assertNull($passkey->lastUsedAt);
        self::assertSame($this->now, $passkey->createdAt);
        self::assertSame('Key', $passkey->name->value);
    }

    public function testARegisteredPasskeyCannotStartWithANegativeCounter(): void
    {
        $this->expectException(InvalidValue::class);

        $this->passkey(signCount: -1);
    }

    public function testAPasskeyCannotBeBackedUpWithoutBeingEligible(): void
    {
        $this->expectException(InvalidValue::class);

        $this->passkey(eligible: false, backedUp: true);
    }

    public function testEligibilityToSyncIsWhatMakesItSynced(): void
    {
        self::assertTrue($this->passkey(eligible: true)->isSynced());
        self::assertFalse($this->passkey(eligible: false)->isSynced());
    }

    public function testAGrowingCounterIsRecordedWithTheTimeAndTheBackupState(): void
    {
        $passkey = $this->passkey(signCount: 4, eligible: true);
        $at = new DateTimeImmutable('2026-02-01T08:00:00Z');

        $passkey->recordUse(5, true, $at);

        self::assertSame(5, $passkey->signCount);
        self::assertTrue($passkey->backedUp);
        self::assertSame($at, $passkey->lastUsedAt);
    }

    public function testACounterThatDoesNotGrowIsARegressionAndChangesNothing(): void
    {
        foreach ([4, 3, 0] as $presented) {
            $passkey = $this->passkey(signCount: 4);

            try {
                $passkey->recordUse($presented, false, $this->now);
                self::fail('A counter of ' . $presented . ' after 4 was accepted.');
            } catch (CounterRegressed $regression) {
                self::assertStringContainsString((string) $presented, $regression->getMessage());
            }
            self::assertSame(4, $passkey->signCount);
            self::assertNull($passkey->lastUsedAt);
        }
    }

    public function testAPasskeyThatCountsIsNotAllowedToStopCounting(): void
    {
        $passkey = $this->passkey(signCount: 0);
        $passkey->recordUse(1, false, $this->now);

        $this->expectException(CounterRegressed::class);

        $passkey->recordUse(0, false, $this->now);
    }

    public function testASyncedPasskeyThatAlwaysReportsZeroIsNotARegression(): void
    {
        $passkey = $this->passkey(signCount: 0, eligible: true);

        $passkey->recordUse(0, true, $this->now);
        $passkey->recordUse(0, true, new DateTimeImmutable('2026-02-01T08:00:00Z'));

        self::assertSame(0, $passkey->signCount);
        self::assertNotNull($passkey->lastUsedAt);
    }

    public function testANegativeCounterIsRefusedAtUse(): void
    {
        $this->expectException(InvalidValue::class);

        $this->passkey()->recordUse(-1, false, $this->now);
    }

    public function testAnAuthenticatorCannotSayItBacksUpAPasskeyItNeverMayBackUp(): void
    {
        $passkey = $this->passkey(eligible: false);

        try {
            $passkey->recordUse(1, true, $this->now);
            self::fail('A device-bound passkey became backed up.');
        } catch (InvalidValue) {
            self::assertFalse($passkey->backedUp);
            self::assertSame(0, $passkey->signCount);
        }
    }

    public function testARenameChangesOnlyTheName(): void
    {
        $passkey = $this->passkey(signCount: 2);

        $passkey->rename(PasskeyName::fromString('Phone'));

        self::assertSame('Phone', $passkey->name->value);
        self::assertSame(2, $passkey->signCount);
    }

    public function testADeviceBoundPasskeyIsAHardwareKeyAndASyncedOneASoftwareKey(): void
    {
        self::assertSame(
            [AuthenticationMethod::HardwareKey],
            $this->passkey(eligible: false)->authenticationMethods(userVerified: true),
        );
        self::assertSame(
            [AuthenticationMethod::SoftwareKey],
            $this->passkey(eligible: true)->authenticationMethods(userVerified: true),
        );
    }

    public function testPresenceWithoutVerificationIsReportedAsSuch(): void
    {
        self::assertSame(
            [AuthenticationMethod::HardwareKey, AuthenticationMethod::UserPresence],
            $this->passkey(eligible: false)->authenticationMethods(userVerified: false),
        );
        self::assertSame(
            [AuthenticationMethod::SoftwareKey, AuthenticationMethod::UserPresence],
            $this->passkey(eligible: true)->authenticationMethods(userVerified: false),
        );
    }

    public function testAPasskeyAfterAPasswordIsMultiFactor(): void
    {
        $passkey = $this->passkey(eligible: true);

        self::assertSame(
            ['pwd', 'swk', 'mfa'],
            array_map(
                static fn (AuthenticationMethod $method): string => $method->value,
                AuthenticationMethod::combined(
                    [AuthenticationMethod::Password],
                    $passkey->authenticationMethods(userVerified: true),
                ),
            ),
        );
    }

    /**
     * @param list<Transport> $transports
     */
    private function passkey(
        int $signCount = 0,
        bool $eligible = false,
        bool $backedUp = false,
        array $transports = [Transport::Internal],
    ): Passkey {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(1)),
            UserId::generate(new SeededRandomSource(2)),
            CredentialId::fromBytes(str_repeat("\x07", 16)),
            CosePublicKey::fromBytes("\xa5\x01"),
            CoseAlgorithm::EdDSA,
            $signCount,
            $transports,
            null,
            $eligible,
            $backedUp,
            PasskeyName::fromString('Key'),
            $this->now,
        );
    }
}
