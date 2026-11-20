<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CredentialsRejected;
use Clavia\Application\Authentication\SignIn\PasswordSignIn;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInOutcome;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class SignInWithPasswordTest extends TestCase
{
    private const string EMAIL = 'jane@example.com';
    private const string PASSWORD = 'correct horse battery staple';
    private const string ADDRESS = '203.0.113.7';

    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private FakePasswordHasher $hasher;
    private InMemoryAttemptCounter $counter;
    private InMemoryLoginStateStore $loginStates;
    private InMemorySessionStore $sessionStore;
    private Sessions $sessions;
    private SignInWithPassword $signIn;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $this->hasher = new FakePasswordHasher();
        $this->counter = new InMemoryAttemptCounter($this->clock);
        $this->loginStates = new InMemoryLoginStateStore($this->clock);
        $this->sessionStore = new InMemorySessionStore($this->clock);
        $this->sessions = new Sessions(
            $this->sessionStore,
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            28800,
            604800,
        );
        $this->signIn = new SignInWithPassword(
            $this->users,
            $this->hasher,
            new LoginThrottle($this->counter, 3, 900),
            $this->loginStates,
            $this->sessions,
        );

        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            self::EMAIL,
            $this->hasher->hash(self::PASSWORD),
            $this->clock->now(),
        );
        $this->users->save($this->user);
    }

    public function testTheRightPasswordStartsAPasswordSessionForTheAccount(): void
    {
        $outcome = $this->attempt();

        self::assertInstanceOf(SignedIn::class, $outcome);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($this->user->id));
        self::assertSame([AuthenticationMethod::Password], $session->methods);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testTheBrowserIsSentBackToThePendingRequestAndTheHandleIsSpent(): void
    {
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?client_id=spa'));

        $outcome = $this->attempt(loginState: 'handle');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/oauth2/authorize?client_id=spa', $outcome->nextUrl);
        self::assertNull($this->loginStates->get('handle'));
    }

    public function testAStoredTargetThatCouldLeaveTheServerIsNotFollowed(): void
    {
        $this->loginStates->put('handle', new LoginState('//evil.example/steal'));

        $outcome = $this->attempt(loginState: 'handle');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testAnUnknownHandleStillSignsInAndLandsOnTheLoginPage(): void
    {
        $outcome = $this->attempt(loginState: 'expired');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testTheSessionTheBrowserHeldIsEnded(): void
    {
        $before = $this->attempt();
        self::assertInstanceOf(SignedIn::class, $before);

        $after = $this->attempt(currentSessionId: $before->sessionId);

        self::assertInstanceOf(SignedIn::class, $after);
        self::assertNull($this->sessions->resolve($before->sessionId));
        self::assertNotNull($this->sessions->resolve($after->sessionId));
    }

    public function testAWrongPasswordIsRejectedAndKeepsThePendingRequest(): void
    {
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?client_id=spa'));

        $outcome = $this->attempt(password: 'wrong', loginState: 'handle');

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        self::assertNotNull($this->loginStates->get('handle'));
        self::assertSame(0, $this->sessionStore->count());
        self::assertSame(1, $this->counter->count('account:' . self::EMAIL));
        self::assertSame(1, $this->counter->count('address:' . self::ADDRESS));
    }

    public function testAnUnknownAccountIsRejectedAfterTheSameWorkAsAWrongPassword(): void
    {
        $outcome = $this->attempt(email: 'nobody@example.com');

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        self::assertSame(1, $this->hasher->simulatedVerifications);
        self::assertSame(1, $this->counter->count('account:nobody@example.com'));
    }

    public function testADeactivatedAccountIsRejectedLikeAnUnknownOne(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        $outcome = $this->attempt();

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        self::assertSame(1, $this->hasher->simulatedVerifications);
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testAnAccountWithoutAPasswordCannotSignInWithOne(): void
    {
        $this->users->save(User::register(
            UserId::generate(new SeededRandomSource(3)),
            'sso@example.com',
            null,
            $this->clock->now(),
        ));

        self::assertInstanceOf(CredentialsRejected::class, $this->attempt(email: 'sso@example.com', password: ''));
        self::assertSame(1, $this->hasher->simulatedVerifications);
    }

    public function testAnEmptyEmailLooksNothingUp(): void
    {
        self::assertInstanceOf(CredentialsRejected::class, $this->attempt(email: ''));
    }

    public function testTheEmailIsMatchedExactly(): void
    {
        self::assertInstanceOf(CredentialsRejected::class, $this->attempt(email: 'JANE@example.com'));
    }

    public function testOnceThrottledEvenTheRightPasswordIsRejectedWithoutBeingChecked(): void
    {
        foreach (range(1, 3) as $ignored) {
            self::assertInstanceOf(CredentialsRejected::class, $this->attempt(password: 'wrong'));
        }

        $outcome = $this->attempt();

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        // The same time spent as any other refusal, and no further failure counted.
        self::assertSame(1, $this->hasher->simulatedVerifications);
        self::assertSame(3, $this->counter->count('account:' . self::EMAIL));
    }

    public function testAnotherAddressIsLockedOutOfAThrottledAccount(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->attempt(password: 'wrong');
        }

        self::assertInstanceOf(CredentialsRejected::class, $this->attempt(clientAddress: '198.51.100.1'));
    }

    public function testASuccessClearsTheCounters(): void
    {
        $this->attempt(password: 'wrong');
        $this->attempt(password: 'wrong');

        self::assertInstanceOf(SignedIn::class, $this->attempt());

        self::assertSame(0, $this->counter->count('account:' . self::EMAIL));
        self::assertSame(0, $this->counter->count('address:' . self::ADDRESS));
    }

    private function attempt(
        string $email = self::EMAIL,
        string $password = self::PASSWORD,
        string $clientAddress = self::ADDRESS,
        ?string $loginState = null,
        ?string $currentSessionId = null,
    ): SignInOutcome {
        return ($this->signIn)(new PasswordSignIn($email, $password, $clientAddress, $loginState, $currentSessionId));
    }
}
