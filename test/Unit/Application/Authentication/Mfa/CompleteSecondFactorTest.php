<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Mfa;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Mfa\ChallengeGone;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Authentication\Mfa\SecondFactorAttempt;
use Clavia\Application\Authentication\Mfa\SecondFactorOutcome;
use Clavia\Application\Authentication\Mfa\SecondFactorRejected;
use Clavia\Application\Authentication\Mfa\TotpSeeds;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakeSecretCipher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * The second step of a sign-in: a code from the app or a recovery code turns an open
 * challenge into a session; anything else is counted, against the challenge and
 * against the account.
 */
final class CompleteSecondFactorTest extends TestCase
{
    private const string ADDRESS = '203.0.113.7';
    private const string HANDLE = 'challenge-handle';

    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private InMemoryMfaChallengeStore $challenges;
    private InMemoryAttemptCounter $counter;
    private InMemorySessionStore $sessionStore;
    private Sessions $sessions;
    private CompleteSecondFactor $complete;
    private TotpSecret $secret;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $transactions = new InMemoryTransactionManager();
        $this->factors = new InMemoryMfaFactorRepository($transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->challenges = new InMemoryMfaChallengeStore($this->clock);
        $this->counter = new InMemoryAttemptCounter($this->clock);
        $this->sessionStore = new InMemorySessionStore($this->clock);
        $this->sessions = new Sessions(
            $this->sessionStore,
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            28800,
            604800,
            new InMemoryDomainEvents(),
        );
        $seeds = new TotpSeeds(new FakeSecretCipher(), 'Clavia');
        $this->complete = new CompleteSecondFactor(
            $this->challenges,
            $this->users,
            $this->factors,
            $this->recoveryCodes,
            $seeds,
            new LoginThrottle($this->counter, 4, 900),
            $this->sessions,
            $transactions,
            $this->clock,
            3,
            new InMemoryDomainEvents(),
        );

        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            'ada@example.com',
            '$hash$',
            $this->clock->now(),
        );
        $this->users->save($this->user);

        // Enrolled one step ago: the step it was confirmed with is spent.
        $this->secret = TotpSecret::generate(new SeededRandomSource(3));
        $enrolledAt = $this->clock->now();
        $factor = MfaFactor::stage($this->user->id, $seeds->seal($this->user->id, $this->secret), $enrolledAt);
        self::assertTrue($factor->accept($this->secret, Totp::codeAt($this->secret, $enrolledAt), $enrolledAt));
        $factor->confirm($enrolledAt);
        $this->factors->save($factor);
        $this->recoveryCodes->replaceAll(
            $this->user->id,
            [RecoveryCode::digest('aaaa-bbbb-cccc'), RecoveryCode::digest('dddd-eeee-ffff')],
            $enrolledAt,
        );
        $this->clock->advance(Totp::PERIOD);

        $this->challenges->open(self::HANDLE, new MfaChallenge(
            $this->user->id,
            '/oauth2/authorize?client_id=spa',
            null,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
        ), 300);
    }

    public function testACodeFromTheAppSignsInWithEveryMethodUsed(): void
    {
        $outcome = $this->enterCode($this->currentCode());

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/oauth2/authorize?client_id=spa', $outcome->nextUrl);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($this->user->id));
        self::assertSame(
            [
                AuthenticationMethod::Password,
                AuthenticationMethod::OneTimePassword,
                AuthenticationMethod::MultipleFactors,
            ],
            $session->methods,
        );
        self::assertNull($this->challenges->find(self::HANDLE), 'A challenge answered is closed.');
        self::assertSame(Totp::timeStep($this->clock->now()), $this->factors->find($this->user->id)?->lastUsedStep);
    }

    public function testARecoveryCodeSignsInOnceWithoutClaimingAnAppCode(): void
    {
        $outcome = $this->enterCode('AAAA-BBBB-CCCC');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame(
            [AuthenticationMethod::Password, AuthenticationMethod::MultipleFactors],
            $this->sessions->resolve($outcome->sessionId)?->methods,
        );
        self::assertSame(1, $this->recoveryCodes->unusedCount($this->user->id));

        $this->reopen();
        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode('aaaa-bbbb-cccc'));
    }

    public function testTheSessionReplacesTheOneTheBrowserHeld(): void
    {
        $previous = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $outcome = $this->enterCode($this->currentCode(), $previous);

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertNotSame($previous, $outcome->sessionId);
        self::assertNull($this->sessions->resolve($previous));
    }

    public function testAWrongCodeIsCountedAndTheLimitEndsTheChallenge(): void
    {
        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode('000000'));
        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode('not-a-code'));
        self::assertSame(2, $this->challenges->find(self::HANDLE)?->attempts);

        self::assertInstanceOf(ChallengeGone::class, $this->enterCode('000000'));
        self::assertNull($this->challenges->find(self::HANDLE));
        self::assertInstanceOf(ChallengeGone::class, $this->enterCode($this->currentCode()));
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testTheStepAlreadySpentIsRefused(): void
    {
        $spent = Totp::codeAt($this->secret, $this->clock->now()->modify('-' . Totp::PERIOD . ' seconds'));

        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode($spent));
    }

    public function testAThrottledAccountHasEvenTheRightCodeRefused(): void
    {
        // A fresh challenge per failure: four wrong guesses spread over challenges still
        // count against the account.
        for ($i = 0; $i < 4; ++$i) {
            $this->reopen();
            $this->enterCode('000000');
        }
        $this->reopen();

        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode($this->currentCode()));
        self::assertSame(0, $this->sessionStore->count());
        self::assertNotSame(
            Totp::timeStep($this->clock->now()),
            $this->factors->find($this->user->id)?->lastUsedStep,
            'A throttled attempt is not even checked, so its code is not spent.',
        );
    }

    public function testSuccessClearsTheFailuresCounted(): void
    {
        $this->enterCode('000000');
        $this->enterCode('000000');
        self::assertInstanceOf(SignedIn::class, $this->enterCode($this->currentCode()));

        for ($i = 0; $i < 3; ++$i) {
            $this->reopen();
            $this->enterCode('000000');
        }
        $this->reopen();
        $this->clock->advance(Totp::PERIOD);
        self::assertInstanceOf(SignedIn::class, $this->enterCode($this->currentCode()));
    }

    public function testAnAccountDeactivatedMeanwhileCannotFinish(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode($this->currentCode()));
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testAnAccountDeletedMeanwhileCannotFinish(): void
    {
        $this->users->delete($this->user->id);

        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode($this->currentCode()));
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testAFactorRemovedMeanwhileAcceptsNothing(): void
    {
        $this->factors->removeAll($this->user->id);

        self::assertInstanceOf(SecondFactorRejected::class, $this->enterCode($this->currentCode()));
    }

    public function testAnUnknownOrEmptyChallengeIsGone(): void
    {
        self::assertInstanceOf(ChallengeGone::class, $this->enterCode($this->currentCode(), challenge: 'unknown'));
        self::assertInstanceOf(ChallengeGone::class, $this->enterCode($this->currentCode(), challenge: ''));
    }

    public function testThePageIsDescribedOnlyForAnOpenChallenge(): void
    {
        $passkeys = new InMemoryPasskeyRepository();
        $describe = new DescribeSecondFactorPage(
            $this->challenges,
            new InMemoryClientRepository(),
            $this->factors,
            $passkeys,
        );

        $page = $describe(self::HANDLE);
        self::assertNotNull($page);
        self::assertSame([], $page->formOrigins);
        self::assertTrue($page->authenticatorApp);
        self::assertFalse($page->passkey);
        self::assertNull($describe('unknown'));
        self::assertNull($describe(''));
        self::assertNull($describe(null));
    }

    private function enterCode(
        string $code,
        ?string $currentSession = null,
        string $challenge = self::HANDLE,
    ): SecondFactorOutcome {
        return ($this->complete)(new SecondFactorAttempt($challenge, $code, self::ADDRESS, $currentSession));
    }

    private function currentCode(): string
    {
        return Totp::codeAt($this->secret, $this->clock->now());
    }

    private function reopen(): void
    {
        $this->challenges->open(self::HANDLE, new MfaChallenge(
            $this->user->id,
            '/',
            null,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
        ), 300);
    }
}
