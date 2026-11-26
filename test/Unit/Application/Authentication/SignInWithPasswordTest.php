<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\Account\AccountMail;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\CredentialsRejected;
use Clavia\Application\Authentication\SignIn\EmailVerificationRequired;
use Clavia\Application\Authentication\SignIn\PasswordSignIn;
use Clavia\Application\Authentication\SignIn\PasswordSignInUnavailable;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInOutcome;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignInRefusal;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryAccountLinkStore;
use ClaviaTest\Support\Fake\InMemoryAttemptCounter;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\TestMail;
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
    private InMemoryMfaFactorRepository $factors;
    private InMemoryMfaChallengeStore $challenges;
    private User $user;
    private InMemoryClientRepository $clients;
    private InMemoryConnectionRepository $connections;
    private RecordingMailer $mailer;
    private InMemoryAccountLinkStore $links;
    private InMemoryDomainEvents $events;

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
            new InMemoryDomainEvents(),
        );
        $this->factors = new InMemoryMfaFactorRepository(new InMemoryTransactionManager());
        $this->challenges = new InMemoryMfaChallengeStore($this->clock);
        $this->clients = new InMemoryClientRepository();
        $this->connections = new InMemoryConnectionRepository($this->clients);
        $this->clients->save(Clients::public('spa'));
        $this->mailer = new RecordingMailer();
        $this->links = new InMemoryAccountLinkStore($this->clock);
        $this->events = new InMemoryDomainEvents();
        $this->signIn = new SignInWithPassword(
            $this->users,
            $this->hasher,
            new LoginThrottle($this->counter, 3, 900),
            $this->loginStates,
            $this->clients,
            new ConnectionAccess($this->connections, new FakeIdentityProviders(), new RecordingMailer(false)),
            new CompleteFirstFactor(
                $this->sessions,
                $this->factors,
                new InMemoryPasskeyRepository(),
                $this->challenges,
                new SecretGenerator(new SeededRandomSource(3)),
                300,
            ),
            $this->events,
            new SendAccountLink(
                $this->links,
                new EmailSendLimit($this->counter, 5, 'account'),
                $this->mailer,
                new AccountMail('clavia.test', 'https://auth.clavia.test', 86400, 1800),
                new SecretGenerator(new SeededRandomSource(4)),
                86400,
                1800,
                TestMail::languages(),
            ),
            $this->clock,
        );

        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            self::EMAIL,
            $this->hasher->hash(self::PASSWORD),
            $this->clock->now(),
        );
        $this->users->save($this->user);
    }

    public function testAnUnverifiedAccountInAPoolRequiringAVerifiedAddressIsSentALinkInsteadOfASession(): void
    {
        $this->requireVerifiedEmail();

        $outcome = $this->signInWith();

        self::assertInstanceOf(EmailVerificationRequired::class, $outcome);
        self::assertSame(self::EMAIL, $outcome->email);
        self::assertSame([], $this->sessions->of($this->user->id));
        self::assertCount(1, $this->links->tokens());
        self::assertSame(self::EMAIL, $this->mailer->last()?->to);
        $refusal = $this->events->ofType(SignInRefused::class)[0] ?? null;
        self::assertSame(SignInRefusal::EmailNotVerified, $refusal?->reason);
    }

    public function testAWrongPasswordForAnUnverifiedAccountSaysNothingAboutVerification(): void
    {
        $this->requireVerifiedEmail();

        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(password: 'not the password'));
        self::assertSame([], $this->mailer->sent);
    }

    public function testAVerifiedAccountSignsInWhereAVerifiedAddressIsRequired(): void
    {
        $this->requireVerifiedEmail();
        $this->user->recordEmailVerification(true, $this->clock->now());
        $this->users->save($this->user);

        self::assertInstanceOf(SignedIn::class, $this->signInWith());
    }

    public function testAnUnverifiedAccountSignsInWhereNoVerifiedAddressIsRequired(): void
    {
        self::assertInstanceOf(SignedIn::class, $this->signInWith());
        self::assertSame([], $this->mailer->sent);
    }

    public function testAnOutdatedHashIsReplacedAtTheNextSignIn(): void
    {
        // An imported hash at another iteration count: the password is at hand only now.
        $before = $this->users->find($this->user->id)?->passwordHash();
        $this->hasher->outdated = true;

        $outcome = $this->signInWith();
        $this->hasher->outdated = false;

        self::assertInstanceOf(SignedIn::class, $outcome);
        $after = $this->users->find($this->user->id)?->passwordHash();
        self::assertNotSame($before, $after);
        self::assertTrue($this->hasher->verify(self::PASSWORD, (string) $after));
    }

    public function testACurrentHashIsLeftAlone(): void
    {
        $before = $this->users->find($this->user->id)?->passwordHash();

        $this->signInWith();

        self::assertSame($before, $this->users->find($this->user->id)?->passwordHash());
    }

    public function testTheRightPasswordStartsAPasswordSessionForTheAccount(): void
    {
        $outcome = $this->signInWith();

        self::assertInstanceOf(SignedIn::class, $outcome);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertNotNull($session);
        self::assertTrue($session->userId->equals($this->user->id));
        self::assertSame([AuthenticationMethod::Password], $session->methods);
        self::assertSame('password', $session->connection->value);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testAnAccountWithAConfirmedFactorGetsAChallengeInsteadOfASession(): void
    {
        $this->enrolSecondFactor();
        $this->loginStates->put(
            'handle',
            new LoginState('/oauth2/authorize?client_id=spa', ClientId::fromString('spa')),
        );

        $outcome = $this->signInWith(loginState: 'handle');

        self::assertInstanceOf(SecondFactorRequired::class, $outcome);
        self::assertSame(0, $this->sessionStore->count());
        self::assertNull($this->loginStates->get('handle'));
        $challenge = $this->challenges->find($outcome->challenge);
        self::assertNotNull($challenge);
        self::assertTrue($challenge->userId->equals($this->user->id));
        self::assertSame('/oauth2/authorize?client_id=spa', $challenge->nextUrl);
        self::assertSame('spa', $challenge->clientId?->value);
        self::assertSame([AuthenticationMethod::Password], $challenge->firstFactor);
        self::assertSame(0, $challenge->attempts);

        $this->clock->advance(300);
        self::assertNull($this->challenges->find($outcome->challenge));
    }

    public function testAFactorStillBeingSetUpDoesNotStandInTheWay(): void
    {
        $this->factors->save(MfaFactor::stage($this->user->id, 'sealed', $this->clock->now()));

        self::assertInstanceOf(SignedIn::class, $this->signInWith());
        self::assertSame(0, $this->challenges->count());
    }

    public function testAWrongPasswordOpensNoChallenge(): void
    {
        $this->enrolSecondFactor();

        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(password: 'wrong'));
        self::assertSame(0, $this->challenges->count());
    }

    public function testTheBrowserIsSentBackToThePendingRequestAndTheHandleIsSpent(): void
    {
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?client_id=spa'));

        $outcome = $this->signInWith(loginState: 'handle');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/oauth2/authorize?client_id=spa', $outcome->nextUrl);
        self::assertNull($this->loginStates->get('handle'));
    }

    public function testAStoredTargetThatCouldLeaveTheServerIsNotFollowed(): void
    {
        $this->loginStates->put('handle', new LoginState('//evil.example/steal'));

        $outcome = $this->signInWith(loginState: 'handle');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testAnUnknownHandleStillSignsInAndLandsOnTheLoginPage(): void
    {
        $outcome = $this->signInWith(loginState: 'expired');

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/auth/login', $outcome->nextUrl);
    }

    public function testTheSessionTheBrowserHeldIsEnded(): void
    {
        $before = $this->signInWith();
        self::assertInstanceOf(SignedIn::class, $before);

        $after = $this->signInWith(currentSessionId: $before->sessionId);

        self::assertInstanceOf(SignedIn::class, $after);
        self::assertNull($this->sessions->resolve($before->sessionId));
        self::assertNotNull($this->sessions->resolve($after->sessionId));
    }

    public function testAWrongPasswordIsRejectedAndKeepsThePendingRequest(): void
    {
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?client_id=spa'));

        $outcome = $this->signInWith(password: 'wrong', loginState: 'handle');

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        self::assertNotNull($this->loginStates->get('handle'));
        self::assertSame(0, $this->sessionStore->count());
        self::assertSame(1, $this->counter->count('account:' . self::EMAIL));
        self::assertSame(1, $this->counter->count('address:' . self::ADDRESS));
    }

    public function testAnUnknownAccountIsRejectedAfterTheSameWorkAsAWrongPassword(): void
    {
        $outcome = $this->signInWith(email: 'nobody@example.com');

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        self::assertSame(1, $this->hasher->simulatedVerifications);
        self::assertSame(1, $this->counter->count('account:nobody@example.com'));
    }

    public function testADeactivatedAccountIsRejectedLikeAnUnknownOne(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        $outcome = $this->signInWith();

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

        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(email: 'sso@example.com', password: ''));
        self::assertSame(1, $this->hasher->simulatedVerifications);
    }

    public function testAnEmptyEmailLooksNothingUp(): void
    {
        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(email: ''));
    }

    public function testTheEmailIsMatchedExactly(): void
    {
        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(email: 'JANE@example.com'));
    }

    public function testOnceThrottledEvenTheRightPasswordIsRejectedWithoutBeingChecked(): void
    {
        foreach (range(1, 3) as $ignored) {
            self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(password: 'wrong'));
        }

        $outcome = $this->signInWith();

        self::assertInstanceOf(CredentialsRejected::class, $outcome);
        // The same time spent as any other refusal, and no further failure counted.
        self::assertSame(1, $this->hasher->simulatedVerifications);
        self::assertSame(3, $this->counter->count('account:' . self::EMAIL));
    }

    public function testAnotherAddressIsLockedOutOfAThrottledAccount(): void
    {
        foreach (range(1, 3) as $ignored) {
            $this->signInWith(password: 'wrong');
        }

        self::assertInstanceOf(CredentialsRejected::class, $this->signInWith(clientAddress: '198.51.100.1'));
    }

    public function testASuccessClearsTheCounters(): void
    {
        $this->signInWith(password: 'wrong');
        $this->signInWith(password: 'wrong');

        self::assertInstanceOf(SignedIn::class, $this->signInWith());

        self::assertSame(0, $this->counter->count('account:' . self::EMAIL));
        self::assertSame(0, $this->counter->count('address:' . self::ADDRESS));
    }

    // ── Connections ──────────────────────────────────────────────────────────────

    public function testAnAccountInAPoolTheApplicationEnablesSignsInAndTheSessionNamesThatPool(): void
    {
        $staff = $this->staffPool();
        $employee = $this->registerIn($staff, self::EMAIL, 'staff-password');
        $this->clients->save(Clients::public('spa')->withConnections([$staff]));
        $this->loginStates->put('handle', self::pendingRequest());

        $outcome = $this->signInWith(password: 'staff-password', loginState: 'handle');

        self::assertInstanceOf(SignedIn::class, $outcome);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertTrue($session?->userId->equals($employee->id));
        self::assertSame('staff', $session?->connection->value);
    }

    public function testAnAccountInAPoolTheApplicationDoesNotUseIsNotEvenTried(): void
    {
        $this->registerIn($this->staffPool(), 'staff@example.com', 'staff-password');
        $this->loginStates->put('handle', self::pendingRequest());

        self::assertInstanceOf(
            CredentialsRejected::class,
            $this->signInWith(email: 'staff@example.com', password: 'staff-password', loginState: 'handle'),
        );
    }

    public function testTheSameAddressInTwoPoolsSignsInToTheOneWhosePasswordMatches(): void
    {
        $staff = $this->staffPool();
        $employee = $this->registerIn($staff, self::EMAIL, 'staff-password');
        $this->clients->save(Clients::public('spa')->withConnections([ConnectionName::defaultPool(), $staff]));
        $this->loginStates->put('handle', self::pendingRequest());
        $this->loginStates->put('again', self::pendingRequest());

        $asEmployee = $this->signInWith(password: 'staff-password', loginState: 'handle');
        $asCustomer = $this->signInWith(loginState: 'again');

        self::assertInstanceOf(SignedIn::class, $asEmployee);
        self::assertInstanceOf(SignedIn::class, $asCustomer);
        self::assertTrue($this->sessions->resolve($asEmployee->sessionId)?->userId->equals($employee->id));
        self::assertTrue($this->sessions->resolve($asCustomer->sessionId)?->userId->equals($this->user->id));
    }

    public function testAnApplicationWithNoPoolCannotTakeAPasswordAtAll(): void
    {
        $this->clients->save(Clients::public('spa')->withConnections([ConnectionName::fromString('google')]));
        $pool = $this->connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->connections->save($pool->switched(null, false, null));
        $this->loginStates->put('handle', self::pendingRequest());

        self::assertInstanceOf(PasswordSignInUnavailable::class, $this->signInWith(loginState: 'handle'));
        self::assertSame(0, $this->counter->count('account:' . self::EMAIL), 'Nothing was attempted.');
        self::assertNotNull($this->loginStates->get('handle'));
    }

    public function testASwitchedOffPoolTakesNoPasswordEvenWithoutAnApplication(): void
    {
        $pool = $this->connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->connections->save($pool->switched(false, null, null));

        self::assertInstanceOf(PasswordSignInUnavailable::class, $this->signInWith());
    }

    private function staffPool(): ConnectionName
    {
        $staff = ConnectionName::fromString('staff');
        $this->connections->add(Connection::pool($staff, 'Staff', true, false, $this->clock->now()));

        return $staff;
    }

    private function registerIn(ConnectionName $pool, string $email, string $password): User
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(crc32($email . $pool->value))),
            $email,
            $this->hasher->hash($password),
            $this->clock->now(),
            $pool,
        );
        $this->users->save($user);

        return $user;
    }

    private static function pendingRequest(): LoginState
    {
        return new LoginState('/oauth2/authorize?client_id=spa', ClientId::fromString('spa'));
    }

    private function signInWith(
        string $email = self::EMAIL,
        string $password = self::PASSWORD,
        string $clientAddress = self::ADDRESS,
        ?string $loginState = null,
        ?string $currentSessionId = null,
    ): SignInOutcome {
        return ($this->signIn)(new PasswordSignIn($email, $password, $clientAddress, $loginState, $currentSessionId));
    }

    private function enrolSecondFactor(): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(4));
        $factor = MfaFactor::stage($this->user->id, 'sealed', $this->clock->now());
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $this->clock->now()), $this->clock->now()));
        $factor->confirm($this->clock->now());
        $this->factors->save($factor);
    }

    private function requireVerifiedEmail(): void
    {
        $pool = $this->connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->connections->save($pool->switched(null, null, null, requiresVerifiedEmail: true));
    }
}
