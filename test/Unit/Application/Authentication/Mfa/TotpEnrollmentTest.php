<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Mfa;

use Clavia\Application\Authentication\Mfa\BeginTotpEnrollment;
use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\DescribeMfa;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Mfa\MfaStatus;
use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\Mfa\TotpEnrollment;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Domain\Authentication\Mfa\FactorAlreadyConfirmed;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\FakeSecretCipher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Turning two-factor authentication on and off: staging a seed, proving the app holds
 * it, the recovery codes that come with it.
 */
final class TotpEnrollmentTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private InMemoryTransactionManager $transactions;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private FakeSecretCipher $cipher;
    private TotpSeeds $seeds;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $this->transactions = new InMemoryTransactionManager();
        $this->factors = new InMemoryMfaFactorRepository($this->transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->cipher = new FakeSecretCipher();
        $this->seeds = new TotpSeeds($this->cipher, 'Clavia (clavia.test)');
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'ada@example.com',
            '$hash$',
            $this->clock->now(),
        );
        $this->users->save($this->user);
    }

    public function testBeginningStagesASealedSeedAndDescribesItForTheApp(): void
    {
        $enrollment = $this->begin();

        $factor = $this->factors->find($this->user->id);
        self::assertNotNull($factor);
        self::assertFalse($factor->isConfirmed());
        self::assertStringNotContainsString($enrollment->secret, $factor->sealedSecret);
        self::assertSame($enrollment->secret, $this->seeds->open($factor)->base32());
        self::assertStringStartsWith(
            'otpauth://totp/Clavia%20%28clavia.test%29%3Aada%40example.com?',
            $enrollment->provisioningUri,
        );
        self::assertStringContainsString('secret=' . $enrollment->secret, $enrollment->provisioningUri);
        self::assertSame(1, $this->transactions->committed);
        self::assertFalse($this->describe()?->enabled);
    }

    public function testBeginningAgainBeforeConfirmingReplacesTheSeed(): void
    {
        $first = $this->begin();
        $second = $this->begin(seed: 3);

        self::assertNotSame($first->secret, $second->secret);
        self::assertSame($second->secret, $this->resume()?->secret);
    }

    public function testAMistypedCodeConfirmsNothingAndTheSameSeedIsShownAgain(): void
    {
        $enrollment = $this->begin();

        self::assertNull($this->confirm('000000') ?? $this->confirm('not a code'));

        self::assertFalse($this->factors->find($this->user->id)?->isConfirmed());
        self::assertSame($enrollment->secret, $this->resume()?->secret);
    }

    public function testTheRightCodeConfirmsTheFactorAndIssuesRecoveryCodes(): void
    {
        $enrollment = $this->begin();

        $codes = $this->confirm($this->codeFor($enrollment));

        self::assertNotNull($codes);
        self::assertCount(4, $codes);
        self::assertTrue($this->factors->find($this->user->id)?->isConfirmed());
        self::assertSame(4, $this->recoveryCodes->unusedCount($this->user->id));
        $spent = $this->recoveryCodes->spend($this->user->id, RecoveryCode::digest($codes[0]), $this->clock->now());
        self::assertTrue($spent);
        $status = $this->describe();
        self::assertNotNull($status);
        self::assertTrue($status->enabled);
        self::assertSame(3, $status->recoveryCodesLeft);
        self::assertSame('ada@example.com', $status->email);
    }

    public function testAConfirmedFactorIsNeitherConfirmedAgainNorResumedNorReplaced(): void
    {
        $enrollment = $this->begin();
        self::assertNotNull($this->confirm($this->codeFor($enrollment)));
        $this->clock->advance(Totp::PERIOD);

        self::assertNull($this->confirm($this->codeFor($enrollment)));
        self::assertNull($this->resume());
        $this->expectException(FactorAlreadyConfirmed::class);
        $this->begin();
    }

    public function testConfirmingWithNothingPendingConfirmsNothing(): void
    {
        self::assertNull($this->confirm('123456'));
        self::assertNull($this->resume());
    }

    public function testAnAccountThatIsGoneHasNoEnrollment(): void
    {
        $this->users->delete($this->user->id);

        self::assertNull($this->tryToBegin());
        self::assertNull($this->factors->find($this->user->id));
        self::assertNull($this->describe());
    }

    public function testTurningItOffRemovesTheFactorAndTheCodesInOneTransaction(): void
    {
        self::assertNotNull($this->confirm($this->codeFor($this->begin())));
        $committed = $this->transactions->committed;

        $disable = new DisableMfa(
            $this->factors,
            $this->recoveryCodes,
            $this->transactions,
            new InMemoryDomainEvents(),
        );
        $disable($this->user->id);

        self::assertNull($this->factors->find($this->user->id));
        self::assertSame(0, $this->recoveryCodes->unusedCount($this->user->id));
        self::assertSame($committed + 1, $this->transactions->committed);
        $this->begin(); // Off means it can be turned on again.
    }

    private function begin(int $seed = 2): TotpEnrollment
    {
        $enrollment = $this->tryToBegin($seed);
        self::assertNotNull($enrollment);

        return $enrollment;
    }

    private function tryToBegin(int $seed = 2): ?TotpEnrollment
    {
        return (new BeginTotpEnrollment(
            $this->users,
            $this->factors,
            $this->seeds,
            $this->transactions,
            new SeededRandomSource($seed),
            $this->clock,
        ))($this->user->id);
    }

    private function describe(): ?MfaStatus
    {
        return (new DescribeMfa($this->users, $this->factors, $this->recoveryCodes))($this->user->id);
    }

    private function resume(): ?TotpEnrollment
    {
        return (new ResumeTotpEnrollment($this->users, $this->factors, $this->seeds))($this->user->id);
    }

    /**
     * @return list<string>|null
     */
    private function confirm(string $code): ?array
    {
        return (new ConfirmTotpEnrollment(
            $this->factors,
            $this->recoveryCodes,
            $this->seeds,
            $this->transactions,
            new SeededRandomSource(9),
            $this->clock,
            4,
            new InMemoryDomainEvents(),
        ))($this->user->id, $code);
    }

    private function codeFor(TotpEnrollment $enrollment): string
    {
        return Totp::codeAt(TotpSecret::fromBase32($enrollment->secret), $this->clock->now());
    }
}
