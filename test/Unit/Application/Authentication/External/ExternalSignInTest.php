<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\External;

use Clavia\Application\Authentication\External\BeginExternalSignIn;
use Clavia\Application\Authentication\External\CompleteExternalSignIn;
use Clavia\Application\Authentication\External\ExternalCallback;
use Clavia\Application\Authentication\External\ExternalSignInFailure;
use Clavia\Application\Authentication\External\ExternalSignInRefused;
use Clavia\Application\Authentication\External\ExternalSignInStarted;
use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakeIdentityProvider;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryExternalIdentityRepository;
use ClaviaTest\Support\Fake\InMemoryExternalSignInStore;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemoryMfaChallengeStore;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Signing in through an external provider, from the use cases' side: the round trip,
 * what the callback refuses, and how an identity finds its account.
 */
final class ExternalSignInTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';
    private const string CALLBACK = 'https://auth.clavia.test/auth/social/idp/callback';

    private FrozenClock $clock;
    private FakeIdentityProvider $provider;
    private InMemoryUserRepository $users;
    private InMemoryExternalIdentityRepository $identities;
    private InMemoryExternalSignInStore $pending;
    private InMemoryLoginStateStore $loginStates;
    private InMemoryMfaFactorRepository $factors;
    private InMemorySessionStore $sessionStore;
    private Sessions $sessions;
    private BeginExternalSignIn $begin;
    private bool $autoLink = true;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->provider = new FakeIdentityProvider();
        $this->users = new InMemoryUserRepository();
        $this->identities = new InMemoryExternalIdentityRepository();
        $this->pending = new InMemoryExternalSignInStore($this->clock);
        $this->loginStates = new InMemoryLoginStateStore($this->clock);
        $this->factors = new InMemoryMfaFactorRepository(new InMemoryTransactionManager());
        $this->sessionStore = new InMemorySessionStore($this->clock);
        $this->sessions = new Sessions(
            $this->sessionStore,
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            28800,
            604800,
        );
        $this->begin = new BeginExternalSignIn(
            new FakeIdentityProviders($this->provider),
            $this->pending,
            $this->loginStates,
            new SecretGenerator(new SeededRandomSource(2)),
            new SeededRandomSource(3),
            self::ISSUER,
        );
    }

    // ── Starting ─────────────────────────────────────────────────────────────────

    public function testAnUnknownProviderStartsNothing(): void
    {
        self::assertNull(($this->begin)('gitlab', null));
        self::assertSame(0, $this->pending->count());
    }

    public function testStartingSendsTheBrowserOutWithAFreshStateAndAPkceChallenge(): void
    {
        $started = $this->start();

        parse_str((string) parse_url($started->authorizationUrl, PHP_URL_QUERY), $query);
        self::assertSame(self::CALLBACK, $query['redirect_uri']);
        self::assertSame($started->handle, $query['state']);
        $pending = $this->pending->claim($started->handle);
        self::assertNotNull($pending);
        self::assertSame(CodeChallenge::forVerifier($pending->codeVerifier)->value, $query['code_challenge']);
        self::assertSame('idp', $pending->provider->value);
        self::assertSame('/auth/login', $pending->nextUrl);
    }

    public function testTheLoginPagesRequestIsCarriedAndAHostileTargetIsNot(): void
    {
        $this->loginStates->put('login', self::pendingRequest());
        $this->loginStates->put('hostile', new LoginState('//evil.example/'));

        $fromLogin = $this->pending->claim($this->start('login')->handle);
        $hostile = $this->pending->claim($this->start('hostile')->handle);

        self::assertSame('/oauth2/authorize?client_id=spa', $fromLogin?->nextUrl);
        self::assertSame('spa', $fromLogin?->clientId?->value);
        self::assertSame('login', $fromLogin?->loginState);
        self::assertSame('/auth/login', $hostile?->nextUrl);
    }

    // ── Completing ───────────────────────────────────────────────────────────────

    public function testAFirstSignInCreatesAVerifiedPasswordLessAccountAndASession(): void
    {
        $started = $this->start();

        $outcome = $this->comeBack($started);

        self::assertInstanceOf(SignedIn::class, $outcome);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertSame([AuthenticationMethod::External], $session?->methods);
        $user = $this->users->findByEmail('ada@example.com');
        self::assertNotNull($user);
        self::assertTrue($session?->userId->equals($user->id));
        self::assertNull($user->passwordHash());
        self::assertTrue($user->isEmailVerified());
        self::assertSame(
            [['code' => 'the-code', 'redirectUri' => self::CALLBACK]],
            array_map(static fn (array $exchange): array => array_slice($exchange, 0, 2), $this->provider->exchanges),
        );
        self::assertSame(0, $this->pending->count());
    }

    public function testTheSignInReturnsToTheRequestAndSpendsTheLoginPagesHandle(): void
    {
        $this->loginStates->put('login', self::pendingRequest());

        $outcome = $this->comeBack($this->start('login'));

        self::assertInstanceOf(SignedIn::class, $outcome);
        self::assertSame('/oauth2/authorize?client_id=spa', $outcome->nextUrl);
        self::assertNull($this->loginStates->get('login'));
    }

    public function testAnAccountWithASecondFactorGetsItsChallenge(): void
    {
        $user = $this->existingUser('ada@example.com');
        $secret = TotpSecret::generate(new SeededRandomSource(9));
        $factor = MfaFactor::stage($user->id, 'sealed', $this->clock->now());
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $this->clock->now()), $this->clock->now()));
        $factor->confirm($this->clock->now());
        $this->factors->save($factor);

        $outcome = $this->comeBack($this->start());

        self::assertInstanceOf(SecondFactorRequired::class, $outcome);
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testTheProviderReportingAnErrorOrSendingNoCodeIsACancellation(): void
    {
        $started = $this->start();

        foreach ([['errorReported' => true], ['code' => null], ['state' => null]] as $callback) {
            self::assertSame(ExternalSignInFailure::Cancelled, $this->refusal($this->comeBack($started, ...$callback)));
        }
        self::assertSame([], $this->provider->exchanges);
    }

    public function testAStateTheBrowserDoesNotHoldIsRefusedWithoutSpendingIt(): void
    {
        $started = $this->start();

        self::assertSame(
            ExternalSignInFailure::StartedInAnotherBrowser,
            $this->refusal($this->comeBack($started, browserState: null)),
        );
        self::assertSame(
            ExternalSignInFailure::StartedInAnotherBrowser,
            $this->refusal($this->comeBack($started, browserState: 'another-state')),
        );
        // The victim's own sign-in was not consumed by the forged callback.
        self::assertInstanceOf(SignedIn::class, $this->comeBack($started));
    }

    public function testAStateWorksOnceAndOnlyForItsProvider(): void
    {
        $started = $this->start();
        self::assertInstanceOf(SignedIn::class, $this->comeBack($started));

        self::assertSame(ExternalSignInFailure::Expired, $this->refusal($this->comeBack($started)));

        $other = new FakeIdentityProvider('other', 'Other');
        $elsewhere = $this->start();
        self::assertSame(
            ExternalSignInFailure::Expired,
            $this->refusal($this->complete(new FakeIdentityProviders($this->provider, $other))(
                new ExternalCallback('other', 'the-code', $elsewhere->handle, false, $elsewhere->handle, null),
            )),
        );
    }

    public function testAnUnknownProviderAtTheCallbackIsNothing(): void
    {
        $started = $this->start();

        self::assertNull($this->complete()(
            new ExternalCallback('gitlab', 'c', $started->handle, false, $started->handle, null),
        ));
    }

    public function testAFailedExchangeIsReportedAsSuch(): void
    {
        $this->provider->fails = true;

        self::assertSame(ExternalSignInFailure::ProviderFailed, $this->refusal($this->comeBack($this->start())));
        self::assertSame(0, $this->sessionStore->count());
    }

    public function testTheRefusalNamesTheProvider(): void
    {
        $this->provider->fails = true;

        $outcome = $this->comeBack($this->start());

        self::assertInstanceOf(ExternalSignInRefused::class, $outcome);
        self::assertSame('Example IdP', $outcome->providerLabel);
    }

    // ── Which account ────────────────────────────────────────────────────────────

    public function testALinkedSubjectSignsInAsItsAccountWhateverTheAddressSaysNow(): void
    {
        $first = $this->signedInUser($this->comeBack($this->start()));
        $this->provider->email = 'ada.new@example.com';

        $again = $this->signedInUser($this->comeBack($this->start()));

        self::assertTrue($again->equals($first));
        self::assertSame('ada@example.com', $this->users->find($first)?->email);
        self::assertNull($this->users->findByEmail('ada.new@example.com'));
        self::assertCount(1, $this->identities->all());
    }

    public function testAVerifiedAddressLinksToTheExistingAccountAndVerifiesIt(): void
    {
        $user = $this->existingUser('Ada@Example.com', verified: false);

        $signedIn = $this->signedInUser($this->comeBack($this->start()));

        self::assertTrue($signedIn->equals($user->id));
        $linked = $this->users->find($user->id);
        self::assertNotNull($linked);
        self::assertTrue($linked->isEmailVerified());
        self::assertSame('$hash$', $linked->passwordHash(), 'The password keeps working alongside.');
        self::assertCount(1, $this->identities->all());
    }

    public function testASecondSubjectWithTheSameVerifiedAddressJoinsTheSameAccount(): void
    {
        $first = $this->signedInUser($this->comeBack($this->start()));
        $this->provider->subject = 'subject-2';

        $second = $this->signedInUser($this->comeBack($this->start()));

        self::assertTrue($second->equals($first));
        self::assertCount(2, $this->identities->all());
    }

    public function testAnAddressTheProviderDoesNotVouchForLinksNothingAndCreatesNothing(): void
    {
        $this->existingUser('ada@example.com');
        $this->provider->emailVerified = false;

        self::assertSame(ExternalSignInFailure::NoVerifiedEmail, $this->refusal($this->comeBack($this->start())));
        $this->provider->email = null;
        self::assertSame(ExternalSignInFailure::NoVerifiedEmail, $this->refusal($this->comeBack($this->start())));

        self::assertSame([], $this->identities->all());
        self::assertCount(1, $this->users->matchingEmail('ada@example.com'));
    }

    public function testLinkingByAddressCanBeSwitchedOff(): void
    {
        $this->autoLink = false;
        $this->existingUser('ada@example.com');

        self::assertSame(ExternalSignInFailure::AddressAlreadyUsed, $this->refusal($this->comeBack($this->start())));
        self::assertSame([], $this->identities->all());
    }

    public function testTwoAccountsMatchingTheAddressIsNoAnswer(): void
    {
        $this->existingUser('ada@example.com');
        $this->existingUser('ADA@example.com');

        self::assertSame(ExternalSignInFailure::AddressAlreadyUsed, $this->refusal($this->comeBack($this->start())));
        self::assertSame([], $this->identities->all());
    }

    public function testADeactivatedAccountIsNotSignedIntoEitherWay(): void
    {
        $user = $this->existingUser('ada@example.com');
        $user->deactivate($this->clock->now());
        $this->users->save($user);

        self::assertSame(ExternalSignInFailure::AccountDisabled, $this->refusal($this->comeBack($this->start())));
        self::assertSame([], $this->identities->all(), 'A deactivated account is not linked to.');

        $this->identities->add(ExternalIdentity::link(
            AssertedIdentity::of($this->provider->name(), 'subject-1', null, false),
            $user->id,
            $this->clock->now(),
        ));
        self::assertSame(ExternalSignInFailure::AccountDisabled, $this->refusal($this->comeBack($this->start())));
    }

    // ─────────────────────────────────────────────────────────────────────────────

    private function start(?string $loginState = null): ExternalSignInStarted
    {
        $started = ($this->begin)('idp', $loginState);
        self::assertNotNull($started);

        return $started;
    }

    private function comeBack(
        ExternalSignInStarted $started,
        ?string $code = 'the-code',
        ?string $state = 'from-start',
        bool $errorReported = false,
        ?string $browserState = 'from-start',
    ): SignedIn|SecondFactorRequired|ExternalSignInRefused|null {
        return $this->complete()(new ExternalCallback(
            'idp',
            $code,
            $state === 'from-start' ? $started->handle : $state,
            $errorReported,
            $browserState === 'from-start' ? $started->handle : $browserState,
            null,
        ));
    }

    private function complete(?FakeIdentityProviders $providers = null): CompleteExternalSignIn
    {
        return new CompleteExternalSignIn(
            $providers ?? new FakeIdentityProviders($this->provider),
            $this->pending,
            new ResolveExternalAccount(
                $this->users,
                $this->identities,
                new InMemoryTransactionManager(),
                new SeededRandomSource(4),
                $this->clock,
                $this->autoLink,
            ),
            $this->loginStates,
            new CompleteFirstFactor(
                $this->sessions,
                $this->factors,
                new InMemoryMfaChallengeStore($this->clock),
                new SecretGenerator(new SeededRandomSource(5)),
                300,
            ),
            self::ISSUER,
        );
    }

    private function refusal(mixed $outcome): ExternalSignInFailure
    {
        self::assertInstanceOf(ExternalSignInRefused::class, $outcome);

        return $outcome->reason;
    }

    private function signedInUser(mixed $outcome): UserId
    {
        self::assertInstanceOf(SignedIn::class, $outcome);
        $session = $this->sessions->resolve($outcome->sessionId);
        self::assertNotNull($session);

        return $session->userId;
    }

    private function existingUser(string $email, bool $verified = true): User
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(crc32($email))),
            $email,
            '$hash$',
            $this->clock->now(),
        );
        $user->recordEmailVerification($verified, $this->clock->now());
        $this->users->save($user);

        return $user;
    }

    private static function pendingRequest(): LoginState
    {
        return new LoginState('/oauth2/authorize?client_id=spa', ClientId::fromString('spa'));
    }
}
