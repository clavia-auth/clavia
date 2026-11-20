<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see MfaFactorRepository} and {@see RecoveryCodeRepository} must do.
 */
trait MfaRepositoriesContract
{
    abstract protected function users(): UserRepository;

    abstract protected function factors(): MfaFactorRepository;

    abstract protected function recoveryCodes(): RecoveryCodeRepository;

    /**
     * @template T
     *
     * @param callable(): T $work
     *
     * @return T
     */
    abstract protected function transactional(callable $work): mixed;

    #[Test]
    public function aStagedFactorIsReadBackWhole(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $this->factors()->save(MfaFactor::stage($userId, 'sealed-1', new DateTimeImmutable('2026-01-15T10:00:00Z')));

        $factor = $this->factors()->find($userId);

        self::assertNotNull($factor);
        self::assertTrue($factor->userId->equals($userId));
        self::assertSame('sealed-1', $factor->sealedSecret);
        self::assertFalse($factor->isConfirmed());
        self::assertNull($factor->lastUsedStep);
        self::assertSame(1768471200, $factor->createdAt->getTimestamp());
    }

    #[Test]
    public function aConfirmedFactorKeepsItsConfirmationAndItsLastStep(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $secret = TotpSecret::generate(new SeededRandomSource(7));
        $factor = MfaFactor::stage($userId, 'sealed-1', $now);
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $now), $now));
        $factor->confirm($now);

        $this->factors()->save($factor);
        $read = $this->factors()->find($userId);

        self::assertNotNull($read);
        self::assertTrue($read->isConfirmed());
        self::assertSame($now->getTimestamp(), $read->confirmedAt?->getTimestamp());
        self::assertSame(Totp::timeStep($now), $read->lastUsedStep);
    }

    #[Test]
    public function savingAgainReplacesTheFactor(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $factor = MfaFactor::stage($userId, 'sealed-1', new DateTimeImmutable('2026-01-15T10:00:00Z'));
        $this->factors()->save($factor);

        $factor->restage('sealed-2');
        $this->factors()->save($factor);

        self::assertSame('sealed-2', $this->factors()->find($userId)?->sealedSecret);
    }

    #[Test]
    public function aChangedFactorIsNotStoredUntilItIsSaved(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $this->factors()->save(MfaFactor::stage($userId, 'sealed-1', new DateTimeImmutable()));

        $this->factors()->find($userId)?->restage('sealed-2');

        self::assertSame('sealed-1', $this->factors()->find($userId)?->sealedSecret);
    }

    #[Test]
    public function anAccountWithoutAFactorHasNone(): void
    {
        self::assertNull($this->factors()->find($this->anAccount('jane@example.com')));
    }

    #[Test]
    public function aFactorIsLockedOnlyInsideATransaction(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $this->factors()->save(MfaFactor::stage($userId, 'sealed-1', new DateTimeImmutable()));

        $locked = $this->transactional(fn (): ?MfaFactor => $this->factors()->lockForVerification($userId));
        self::assertSame('sealed-1', $locked?->sealedSecret);

        $this->expectException(LogicException::class);
        $this->factors()->lockForVerification($userId);
    }

    #[Test]
    public function removingTheFactorsRemovesThemAndDoingItTwiceIsDoingItOnce(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $other = $this->anAccount('john@example.com');
        $this->factors()->save(MfaFactor::stage($userId, 'sealed-1', new DateTimeImmutable()));
        $this->factors()->save(MfaFactor::stage($other, 'sealed-2', new DateTimeImmutable()));

        $this->factors()->removeAll($userId);
        $this->factors()->removeAll($userId);

        self::assertNull($this->factors()->find($userId));
        self::assertNotNull($this->factors()->find($other));
    }

    #[Test]
    public function onlyConfirmedFactorsCountAmongAccounts(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $confirmed = $this->anAccount('jane@example.com');
        $pending = $this->anAccount('john@example.com');
        $none = $this->anAccount('jim@example.com');
        $secret = TotpSecret::generate(new SeededRandomSource(7));
        $factor = MfaFactor::stage($confirmed, 'sealed-1', $now);
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $now), $now));
        $factor->confirm($now);
        $this->factors()->save($factor);
        $this->factors()->save(MfaFactor::stage($pending, 'sealed-2', $now));

        $among = $this->factors()->confirmedAmong([$none, $pending, $confirmed]);

        self::assertSame([$confirmed->value], array_map(static fn (UserId $id): string => $id->value, $among));
        self::assertSame([], $this->factors()->confirmedAmong([]));
    }

    #[Test]
    public function aRecoveryCodeIsSpentOnceAndOnlyByItsAccount(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $other = $this->anAccount('john@example.com');
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->recoveryCodes()->replaceAll($userId, [
            RecoveryCode::digest('aaaa-bbbb-cccc'),
            RecoveryCode::digest('dddd-eeee-ffff'),
        ], $now);

        self::assertSame(2, $this->recoveryCodes()->unusedCount($userId));
        self::assertFalse($this->recoveryCodes()->spend($other, RecoveryCode::digest('aaaa-bbbb-cccc'), $now));
        self::assertTrue($this->recoveryCodes()->spend($userId, RecoveryCode::digest('aaaa-bbbb-cccc'), $now));
        self::assertFalse($this->recoveryCodes()->spend($userId, RecoveryCode::digest('aaaa-bbbb-cccc'), $now));
        self::assertFalse($this->recoveryCodes()->spend($userId, RecoveryCode::digest('gggg-hhhh-jjjj'), $now));
        self::assertSame(1, $this->recoveryCodes()->unusedCount($userId));
        self::assertSame(0, $this->recoveryCodes()->unusedCount($other));
    }

    #[Test]
    public function issuingANewSetInvalidatesTheOldOne(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $this->recoveryCodes()->replaceAll($userId, [RecoveryCode::digest('aaaa-bbbb-cccc')], $now);

        $this->recoveryCodes()->replaceAll($userId, [
            RecoveryCode::digest('dddd-eeee-ffff'),
            RecoveryCode::digest('gggg-hhhh-jjjj'),
            RecoveryCode::digest('kkkk-mmmm-nnnn'),
        ], $now);

        self::assertSame(3, $this->recoveryCodes()->unusedCount($userId));
        self::assertFalse($this->recoveryCodes()->spend($userId, RecoveryCode::digest('aaaa-bbbb-cccc'), $now));
        self::assertTrue($this->recoveryCodes()->spend($userId, RecoveryCode::digest('kkkk-mmmm-nnnn'), $now));
    }

    #[Test]
    public function removingTheRecoveryCodesRemovesThemAndDoingItTwiceIsDoingItOnce(): void
    {
        $userId = $this->anAccount('jane@example.com');
        $now = new DateTimeImmutable();
        $this->recoveryCodes()->replaceAll($userId, [RecoveryCode::digest('aaaa-bbbb-cccc')], $now);

        $this->recoveryCodes()->removeAll($userId);
        $this->recoveryCodes()->removeAll($userId);

        self::assertSame(0, $this->recoveryCodes()->unusedCount($userId));
        self::assertFalse($this->recoveryCodes()->spend($userId, RecoveryCode::digest('aaaa-bbbb-cccc'), $now));
    }

    private function anAccount(string $email): UserId
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(crc32($email))),
            $email,
            '$hash$',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users()->save($user);

        return $user->id;
    }
}
