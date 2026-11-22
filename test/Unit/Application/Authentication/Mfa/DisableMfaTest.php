<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Mfa;

use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorType;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * Turning the authenticator app off, and what becomes of the recovery codes: they are the way
 * back for every second factor, so they stay while a passkey does — unless an operator resets the
 * account, which is for somebody who lost their codes too.
 */
final class DisableMfaTest extends TestCase
{
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private InMemoryPasskeyRepository $passkeys;
    private UserId $user;
    private DateTimeImmutable $now;

    #[\Override]
    protected function setUp(): void
    {
        $transactions = new InMemoryTransactionManager();
        $this->factors = new InMemoryMfaFactorRepository($transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->passkeys = new InMemoryPasskeyRepository();
        $this->user = UserId::generate(new SeededRandomSource(1));
        $this->now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->factors->save(MfaFactor::reconstitute($this->user, MfaFactorType::Totp, 's', $this->now, 1, $this->now));
        $this->recoveryCodes->replaceAll($this->user, [Digest::of('a'), Digest::of('b')], $this->now);
    }

    public function testWithoutAPasskeyTheCodesGoWithTheApp(): void
    {
        $this->disable()($this->user);

        self::assertNull($this->factors->find($this->user));
        self::assertSame(0, $this->recoveryCodes->unusedCount($this->user));
    }

    public function testThePersonsCodesStayWithTheirPasskeys(): void
    {
        $this->passkeys->save($this->passkey());

        $this->disable()($this->user);

        self::assertNull($this->factors->find($this->user));
        self::assertSame(2, $this->recoveryCodes->unusedCount($this->user));
        self::assertCount(1, $this->passkeys->ofUser($this->user));
    }

    public function testAnOperatorsResetTakesTheCodesAndLeavesThePasskeys(): void
    {
        $this->passkeys->save($this->passkey());

        $this->disable()($this->user, byTheirOwner: false);

        self::assertSame(0, $this->recoveryCodes->unusedCount($this->user));
        self::assertCount(1, $this->passkeys->ofUser($this->user), 'Passkeys are removed one by one.');
    }

    private function disable(): DisableMfa
    {
        return new DisableMfa(
            $this->factors,
            $this->recoveryCodes,
            $this->passkeys,
            new InMemoryTransactionManager(),
            new InMemoryDomainEvents(),
        );
    }

    private function passkey(): Passkey
    {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(2)),
            $this->user,
            CredentialId::fromBytes(str_repeat("\x01", 16)),
            CosePublicKey::fromBytes('k'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString('Key'),
            $this->now,
        );
    }
}
