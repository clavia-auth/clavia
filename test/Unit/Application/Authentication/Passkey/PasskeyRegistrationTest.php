<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication\Passkey;

use Clavia\Application\Authentication\Passkey\BeginPasskeyRegistration;
use Clavia\Application\Authentication\Passkey\CompletePasskeyRegistration;
use Clavia\Application\Authentication\Passkey\PasskeyAdded;
use Clavia\Application\Authentication\Passkey\PasskeyChange;
use Clavia\Application\Authentication\Passkey\PasskeyLimitReached;
use Clavia\Application\Authentication\Passkey\PasskeyNotAdded;
use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Application\Authentication\Passkey\RegistrationOptions;
use Clavia\Application\Authentication\Passkey\RemovePasskey;
use Clavia\Application\Authentication\Passkey\RenamePasskey;
use Clavia\Application\Authentication\Passkey\SignInAgain;
use Clavia\Application\Port\VerifiedRegistration;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\PasskeyRegistered;
use Clavia\Domain\Authentication\Event\PasskeyRemoved;
use Clavia\Domain\Authentication\Event\PasskeyRenamed;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\MfaFactorType;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasskeyVerifier;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryExternalIdentityRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\InMemoryWebAuthnChallengeStore;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Registering, renaming and removing passkeys: the rules of docs/design/passkeys.md §6.1 and
 * §6.4, with every port a double and the verifier told what to answer.
 */
final class PasskeyRegistrationTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private InMemoryPasskeyRepository $passkeys;
    private InMemoryWebAuthnChallengeStore $ceremonies;
    private InMemoryTransactionManager $transactions;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private FakePasskeyVerifier $verifier;
    private InMemoryDomainEvents $events;
    private InMemoryExternalIdentityRepository $identities;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $this->passkeys = new InMemoryPasskeyRepository();
        $this->ceremonies = new InMemoryWebAuthnChallengeStore($this->clock);
        $this->transactions = new InMemoryTransactionManager();
        $this->factors = new InMemoryMfaFactorRepository($this->transactions);
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->verifier = new FakePasskeyVerifier();
        $this->events = new InMemoryDomainEvents();
        $this->identities = new InMemoryExternalIdentityRepository();
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'ada@example.com',
            '$2y$12$hash',
            $this->clock->now(),
        );
        $this->users->save($this->user);
        $this->verifier->acceptRegistrationsAs($this->verified('first'));
    }

    // ── Beginning ─────────────────────────────────────────────────────────────────────────────

    public function testTheOptionsAreForThisAccountAndExcludeItsPasskeys(): void
    {
        $this->passkeys->save($this->passkey('existing'));

        $options = $this->begin()($this->session());

        self::assertInstanceOf(RegistrationOptions::class, $options);
        self::assertTrue($options->challenge->userId?->equals($this->user->id));
        self::assertSame('ada@example.com', $options->userName);
        self::assertCount(1, $options->exclude);
        $opened = $this->ceremonies->claim($options->handle);
        self::assertNotNull($opened);
        self::assertSame($options->challenge->challenge, $opened->challenge);
    }

    public function testASessionSignedInTooLongAgoMustSignInAgain(): void
    {
        $session = $this->session();
        $this->clock->advance(601);

        self::assertInstanceOf(SignInAgain::class, $this->begin()($session));
    }

    public function testTheWindowIsInclusive(): void
    {
        $session = $this->session();
        $this->clock->advance(600);

        self::assertInstanceOf(RegistrationOptions::class, $this->begin()($session));
    }

    public function testAnAccountAtItsLimitOpensNoCeremony(): void
    {
        $this->passkeys->save($this->passkey('one'));

        $outcome = $this->begin(max: 1)($this->session());

        self::assertEquals(new PasskeyLimitReached(1), $outcome);
    }

    public function testADeactivatedAccountOpensNothing(): void
    {
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        self::assertNull($this->begin()($this->session()));
    }

    // ── Completing ────────────────────────────────────────────────────────────────────────────

    public function testTheFirstPasskeyIsSavedAnnouncedAndBringsRecoveryCodes(): void
    {
        $handle = $this->openCeremony();

        $outcome = $this->complete()($this->session(), $handle, '{}', 'Laptop');

        self::assertInstanceOf(PasskeyAdded::class, $outcome);
        self::assertSame('Laptop', $outcome->name->value);
        self::assertCount(10, $outcome->recoveryCodes ?? []);
        self::assertSame(10, $this->recoveryCodes->unusedCount($this->user->id));
        self::assertCount(1, $this->passkeys->ofUser($this->user->id));
        self::assertCount(1, $this->events->ofType(PasskeyRegistered::class));
    }

    public function testAnAccountWithAnAuthenticatorAppGetsNoNewCodes(): void
    {
        $this->factors->save(MfaFactor::reconstitute(
            $this->user->id,
            MfaFactorType::Totp,
            'sealed',
            $this->clock->now(),
            1,
            $this->clock->now(),
        ));

        $outcome = $this->complete()($this->session(), $this->openCeremony(), '{}', 'Laptop');

        self::assertInstanceOf(PasskeyAdded::class, $outcome);
        self::assertNull($outcome->recoveryCodes);
    }

    public function testAnAccountThatStillHoldsRecoveryCodesGetsNoNewOnes(): void
    {
        $this->recoveryCodes->replaceAll($this->user->id, [Digest::of('kept')], $this->clock->now());

        $outcome = $this->complete()($this->session(), $this->openCeremony(), '{}', 'Laptop');

        self::assertInstanceOf(PasskeyAdded::class, $outcome);
        self::assertNull($outcome->recoveryCodes);
        self::assertSame(1, $this->recoveryCodes->unusedCount($this->user->id));
    }

    public function testACeremonyIsSpentEvenWhenTheResponseIsRefused(): void
    {
        $handle = $this->openCeremony();
        $this->verifier->rejectEverything();

        self::assertSame(PasskeyNotAdded::Rejected, $this->complete()($this->session(), $handle, '{}', ''));

        $this->verifier->acceptRegistrationsAs($this->verified('first'));
        self::assertSame(PasskeyNotAdded::CeremonyGone, $this->complete()($this->session(), $handle, '{}', ''));
        self::assertSame([], $this->passkeys->ofUser($this->user->id));
    }

    public function testACeremonyOfAnotherAccountOrPurposeOrPastItsTimeIsGone(): void
    {
        $other = UserId::generate(new SeededRandomSource(9));
        $this->ceremonies->open(
            'other-account',
            WebAuthnChallenge::forRegistration(new SeededRandomSource(2), $other, $this->clock->now(), 300),
            300,
        );
        $this->ceremonies->open(
            'sign-in',
            WebAuthnChallenge::forSignIn(new SeededRandomSource(3), 'login-state', $this->clock->now(), 300),
            300,
        );
        $this->ceremonies->open(
            'stale',
            WebAuthnChallenge::forRegistration(new SeededRandomSource(4), $this->user->id, $this->clock->now(), 60),
            300,
        );
        $this->clock->advance(61);

        foreach (['other-account', 'sign-in', 'stale', 'never-opened', ''] as $handle) {
            self::assertSame(
                PasskeyNotAdded::CeremonyGone,
                $this->complete()($this->session(), $handle, '{}', ''),
                $handle,
            );
        }
        self::assertSame([], $this->verifier->asked, 'Nothing was verified for a ceremony that is gone.');
    }

    public function testANameThatCannotBeAPasskeysIsRefusedBeforeAnythingIsVerified(): void
    {
        $outcome = $this->complete()($this->session(), $this->openCeremony(), '{}', str_repeat('a', 65));

        self::assertSame(PasskeyNotAdded::InvalidName, $outcome);
        self::assertSame([], $this->verifier->asked);
    }

    public function testACredentialRegisteredBeforeIsRefusedAsSuch(): void
    {
        $this->passkeys->save($this->passkey('first'));

        $outcome = $this->complete()($this->session(), $this->openCeremony(), '{}', 'Again');

        self::assertSame(PasskeyNotAdded::AlreadyRegistered, $outcome);
        self::assertSame([], $this->events->ofType(PasskeyRegistered::class));
    }

    public function testTheLimitIsCheckedAgainWhenTheAnswerArrives(): void
    {
        $handle = $this->openCeremony();
        $this->passkeys->save($this->passkey('meanwhile'));

        $outcome = $this->complete(max: 1)($this->session(), $handle, '{}', 'Too many');

        self::assertEquals(new PasskeyLimitReached(1), $outcome);
    }

    public function testCompletingAlsoNeedsARecentSignIn(): void
    {
        $session = $this->session();
        $handle = $this->openCeremony();
        $this->clock->advance(601);

        self::assertInstanceOf(SignInAgain::class, $this->complete()($session, $handle, '{}', ''));
        self::assertSame([], $this->passkeys->ofUser($this->user->id));
    }

    // ── Renaming and removing ─────────────────────────────────────────────────────────────────

    public function testAPasskeyIsRenamedAndRemovedByItsOwner(): void
    {
        $passkey = $this->passkey('mine');
        $this->passkeys->save($passkey);
        $recent = new RecentSignIn($this->clock, 600);

        $rename = new RenamePasskey($this->passkeys, $this->events, $recent);
        $renamed = $rename($this->session(), $passkey->id->value, 'Phone');
        $removed = $this->remove($recent)($this->session(), $passkey->id->value);

        self::assertSame(PasskeyChange::Done, $renamed);
        self::assertSame(PasskeyChange::Done, $removed);
        self::assertSame([], $this->passkeys->ofUser($this->user->id));
        self::assertSame('Phone', $this->events->ofType(PasskeyRenamed::class)[0]->name->value);
        self::assertTrue($this->events->ofType(PasskeyRemoved::class)[0]->byTheirOwner);
    }

    public function testSomebodyElsesPasskeyIsNotFoundAndUntouched(): void
    {
        $theirs = Passkey::register(
            PasskeyId::generate(new SeededRandomSource(20)),
            UserId::generate(new SeededRandomSource(21)),
            CredentialId::fromBytes(hash('sha256', 'theirs', true)),
            CosePublicKey::fromBytes('k'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString('Theirs'),
            $this->clock->now(),
        );
        $this->passkeys->save($theirs);
        $recent = new RecentSignIn($this->clock, 600);

        foreach ([$theirs->id->value, 'not-an-id', '00000000-0000-4000-8000-000000000000'] as $id) {
            self::assertSame(
                PasskeyChange::NotFound,
                new RenamePasskey($this->passkeys, $this->events, $recent)($this->session(), $id, 'Mine now'),
            );
            self::assertSame(
                PasskeyChange::NotFound,
                $this->remove($recent)($this->session(), $id),
            );
        }
        self::assertSame('Theirs', $this->passkeys->one($theirs->id)?->name->value);
        self::assertSame([], $this->events->all());
    }

    public function testRenamingAndRemovingNeedARecentSignIn(): void
    {
        $passkey = $this->passkey('mine');
        $this->passkeys->save($passkey);
        $session = $this->session();
        $this->clock->advance(601);
        $recent = new RecentSignIn($this->clock, 600);

        self::assertInstanceOf(
            SignInAgain::class,
            new RenamePasskey($this->passkeys, $this->events, $recent)($session, $passkey->id->value, 'Phone'),
        );
        self::assertInstanceOf(
            SignInAgain::class,
            $this->remove($recent)($session, $passkey->id->value),
        );
        self::assertCount(1, $this->passkeys->ofUser($this->user->id));
    }

    public function testTheLastPasskeyOfAnAccountWithNoOtherWayInStays(): void
    {
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(31)),
            'nopassword@example.com',
            null,
            $this->clock->now(),
        );
        $this->users->save($this->user);
        $only = $this->passkey('only');
        $this->passkeys->save($only);
        $remove = $this->remove(new RecentSignIn($this->clock, 600));

        self::assertSame(PasskeyChange::LastWayIn, $remove($this->session(), $only->id->value));
        self::assertCount(1, $this->passkeys->ofUser($this->user->id));

        // With a second passkey, either may go — but then the other is the last.
        $second = $this->passkey('second');
        $this->passkeys->save($second);
        self::assertSame(PasskeyChange::Done, $remove($this->session(), $only->id->value));
        self::assertSame(PasskeyChange::LastWayIn, $remove($this->session(), $second->id->value));
    }

    public function testAnIdentityAtAnotherProviderIsAWayIn(): void
    {
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(32)),
            'linked@example.com',
            null,
            $this->clock->now(),
        );
        $this->users->save($this->user);
        $this->identities->add(ExternalIdentity::link(
            AssertedIdentity::of(ConnectionName::fromString('google'), 'g-1', null, false),
            $this->user->id,
            $this->clock->now(),
        ));
        $only = $this->passkey('only');
        $this->passkeys->save($only);

        self::assertSame(
            PasskeyChange::Done,
            $this->remove(new RecentSignIn($this->clock, 600))($this->session(), $only->id->value),
        );
    }

    // ── What the tests above are made of ──────────────────────────────────────────────────────

    private function remove(RecentSignIn $recent): RemovePasskey
    {
        return new RemovePasskey(
            $this->passkeys,
            $this->users,
            new InMemoryConnectionRepository(),
            $this->identities,
            $this->events,
            $recent,
        );
    }

    /** @param positive-int $max */
    private function begin(int $max = 10): BeginPasskeyRegistration
    {
        return new BeginPasskeyRegistration(
            $this->users,
            $this->passkeys,
            $this->ceremonies,
            new SecretGenerator(new SeededRandomSource(5)),
            new SeededRandomSource(6),
            $this->clock,
            $this->rp(),
            new RecentSignIn($this->clock, 600),
            300,
            $max,
        );
    }

    /** @param positive-int $max */
    private function complete(int $max = 10): CompletePasskeyRegistration
    {
        return new CompletePasskeyRegistration(
            $this->ceremonies,
            $this->verifier,
            $this->passkeys,
            $this->factors,
            $this->recoveryCodes,
            $this->transactions,
            $this->events,
            new SeededRandomSource(7),
            $this->clock,
            $this->rp(),
            new RecentSignIn($this->clock, 600),
            $max,
            10,
        );
    }

    /** @return non-empty-string */
    private function openCeremony(): string
    {
        $options = $this->begin()($this->session());
        self::assertInstanceOf(RegistrationOptions::class, $options);

        return $options->handle;
    }

    /** A session of the account, signed in now. */
    private function session(): Session
    {
        return Session::establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            'sid',
            $this->clock->now(),
            86400,
        );
    }

    private function rp(): RelyingParty
    {
        return RelyingParty::of('auth.clavia.test', 'Clavia', 'https://auth.clavia.test');
    }

    private function verified(string $seed): VerifiedRegistration
    {
        return new VerifiedRegistration(
            CredentialId::fromBytes(hash('sha256', $seed, true)),
            CosePublicKey::fromBytes('key'),
            CoseAlgorithm::ES256,
            0,
            [Transport::Internal],
            null,
            false,
            false,
            true,
        );
    }

    private function passkey(string $seed): Passkey
    {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(crc32($seed))),
            $this->user->id,
            CredentialId::fromBytes(hash('sha256', $seed, true)),
            CosePublicKey::fromBytes('key'),
            CoseAlgorithm::ES256,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString($seed),
            $this->clock->now(),
        );
    }
}
