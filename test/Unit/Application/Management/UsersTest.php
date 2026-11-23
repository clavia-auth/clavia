<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Authentication\Account\PasswordScreen;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\NewUser;
use Clavia\Application\Management\Users\ReadIdentities;
use Clavia\Application\Management\Users\ReadUserPasskeys;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\RemoveUserPasskey;
use Clavia\Application\Management\Users\ResetUserMfa;
use Clavia\Application\Management\Users\UnlinkIdentity;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Management\Users\UserChanges;
use Clavia\Domain\Authentication\Event\PasskeyRemoved;
use Clavia\Domain\Authentication\Mfa\MfaFactor;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\Totp;
use Clavia\Domain\Authentication\Mfa\TotpSecret;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\BackChannelLogouts;
use ClaviaTest\Support\Fake\FakeBreachedPasswords;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryExternalIdentityRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryRecoveryCodeRepository;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Creating, changing, reading and deleting end users through the Management API's use cases.
 */
final class UsersTest extends TestCase
{
    private InMemoryUserRepository $users;
    private const string BREACHED_PASSWORD = 'password123';

    private FakePasswordHasher $hasher;
    private FrozenClock $clock;
    private InMemoryTransactionManager $transactions;
    private InMemoryMfaFactorRepository $factors;
    private InMemoryPasskeyRepository $passkeys;
    private InMemoryRecoveryCodeRepository $recoveryCodes;
    private InMemoryConnectionRepository $connections;
    private InMemoryExternalIdentityRepository $identities;
    private Sessions $sessions;
    private SignOutEverywhere $signOut;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->hasher = new FakePasswordHasher();
        $this->clock = new FrozenClock();
        $this->transactions = new InMemoryTransactionManager();
        $this->factors = new InMemoryMfaFactorRepository($this->transactions);
        $this->passkeys = new InMemoryPasskeyRepository();
        $this->recoveryCodes = new InMemoryRecoveryCodeRepository();
        $this->connections = new InMemoryConnectionRepository();
        $this->identities = new InMemoryExternalIdentityRepository();
        $this->sessions = new Sessions(
            new InMemorySessionStore($this->clock),
            new SecretGenerator(new SeededRandomSource(4)),
            $this->clock,
            28800,
            604800,
            new InMemoryDomainEvents(),
        );
        [$backChannel] = BackChannelLogouts::for(new InMemoryClientRepository(), $this->clock);
        $this->signOut = new SignOutEverywhere($this->sessions, new InMemoryDomainEvents($backChannel));
    }

    public function testACreatedUserHasAHashedPasswordAndTheStandingAsked(): void
    {
        $user = $this->create(new NewUser(
            'ada@example.com',
            'a-good-password',
            emailVerified: true,
            isActive: false,
            profile: ['name' => 'Ada', 'locale' => 'en-GB'],
        ));

        $stored = $this->users->find($user->id);
        self::assertNotNull($stored);
        self::assertTrue($this->hasher->verify('a-good-password', (string) $stored->passwordHash()));
        self::assertNotSame('a-good-password', $stored->passwordHash());
        self::assertTrue($stored->isEmailVerified());
        self::assertFalse($stored->isActive());
        self::assertSame('Ada', $stored->profile()->name);
        self::assertSame('en-GB', $stored->profile()->locale);
    }

    public function testAPasswordOutsideThePolicyIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->create(new NewUser('ada@example.com', 'short'));
    }

    public function testABreachedPasswordIsRefusedAtCreation(): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessageIsOrContains(PasswordScreen::BREACHED);

        $this->create(new NewUser('ada@example.com', self::BREACHED_PASSWORD));
    }

    public function testABreachedPasswordIsRefusedAsAChangeAndLeavesTheOldOne(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $before = $this->users->find($user->id)?->passwordHash();

        try {
            ($this->update())($user->id, new UserChanges(password: self::BREACHED_PASSWORD));
            self::fail('A breached password is refused.');
        } catch (InvalidValue $refusal) {
            self::assertSame(PasswordScreen::BREACHED, $refusal->getMessage());
        }
        self::assertSame($before, $this->users->find($user->id)?->passwordHash());
    }

    public function testAUserCreatedWithoutAPasswordHasNone(): void
    {
        $user = $this->create(new NewUser('ada@example.com'));

        self::assertNull($this->users->find($user->id)?->passwordHash());
    }

    public function testAnAddressAlreadyUsedIsRefusedAsSuch(): void
    {
        $this->create(new NewUser('ada@example.com', 'a-good-password'));

        $this->expectException(AlreadyExists::class);

        $this->create(new NewUser('ada@example.com', 'another-password'));
    }

    public function testAnUpdateChangesOnlyWhatItNames(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', profile: ['name' => 'Ada']));

        $updated = $this->update()($user->id, new UserChanges(profile: ['nickname' => 'ada']))->user;

        self::assertSame('ada@example.com', $updated->email);
        self::assertSame('Ada', $updated->profile()->name);
        self::assertSame('ada', $updated->profile()->nickname);
        self::assertTrue($this->hasher->verify('a-good-password', (string) $updated->passwordHash()));
    }

    public function testAProfileFieldSetToNullIsCleared(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', profile: ['name' => 'Ada']));

        self::assertNull($this->update()($user->id, new UserChanges(profile: ['name' => null]))->user->profile()->name);
    }

    public function testANewAddressIsUnverifiedUnlessTheSameChangeSaysOtherwise(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', emailVerified: true));

        self::assertFalse(
            $this->update()($user->id, new UserChanges(email: 'ada@new.example'))->user->isEmailVerified(),
        );
        self::assertTrue(
            $this->update()($user->id, new UserChanges(email: 'ada@other.example', emailVerified: true))
                ->user->isEmailVerified(),
        );
    }

    public function testAPasswordChangeIsHashedAndChecked(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));

        $updated = $this->update()($user->id, new UserChanges(password: 'another-password'))->user;
        self::assertTrue($this->hasher->verify('another-password', (string) $updated->passwordHash()));

        $this->expectException(InvalidValue::class);
        $this->update()($user->id, new UserChanges(password: str_repeat('a', 73)));
    }

    public function testDeactivatingAndReactivating(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));

        self::assertFalse($this->update()($user->id, new UserChanges(isActive: false))->user->isActive());
        self::assertTrue($this->update()($user->id, new UserChanges(isActive: true))->user->isActive());
    }

    public function testAUserIsReportedEnrolledOnlyOnceItsFactorIsConfirmed(): void
    {
        $enrolled = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $pending = $this->create(new NewUser('bob@example.com', 'a-good-password'));
        $this->enrol($enrolled);
        $this->factors->save(MfaFactor::stage($pending->id, 'sealed', $this->clock->now()));
        $read = new ReadUsers($this->users, $this->factors, $this->passkeys);

        self::assertTrue($read->one($enrolled->id)->mfaEnrolled);
        self::assertFalse($read->one($pending->id)->mfaEnrolled);
        self::assertTrue(
            $this->update()($enrolled->id, new UserChanges(profile: ['nickname' => 'ada']))->mfaEnrolled,
        );

        $listed = [];
        foreach ($read->page(PageRequest::of())->items as $managed) {
            $listed[$managed->user->email] = $managed->mfaEnrolled;
        }
        self::assertSame(['bob@example.com' => false, 'ada@example.com' => true], $listed, 'Newest first.');
    }

    public function testResettingTheSecondFactorRemovesTheFactorAndTheRecoveryCodes(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $this->enrol($user);
        $this->recoveryCodes->replaceAll($user->id, [RecoveryCode::digest('aaaa-bbbb-cccc')], $this->clock->now());
        $reset = new ResetUserMfa(
            $this->users,
            new DisableMfa(
                $this->factors,
                $this->recoveryCodes,
                new InMemoryPasskeyRepository(),
                $this->transactions,
                new InMemoryDomainEvents(),
            ),
        );

        $reset($user->id);
        $reset($user->id);

        self::assertNull($this->factors->find($user->id));
        self::assertSame(0, $this->recoveryCodes->unusedCount($user->id));
        self::assertFalse(new ReadUsers($this->users, $this->factors, $this->passkeys)->one($user->id)->mfaEnrolled);
    }

    public function testResettingTheSecondFactorOfAnUnknownUserIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        $reset = new ResetUserMfa(
            $this->users,
            new DisableMfa(
                $this->factors,
                $this->recoveryCodes,
                new InMemoryPasskeyRepository(),
                $this->transactions,
                new InMemoryDomainEvents(),
            ),
        );
        $reset(UserId::generate(new SeededRandomSource(9)));
    }

    public function testAnUnknownUserIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ReadUsers($this->users, $this->factors, $this->passkeys)->one(UserId::generate(new SeededRandomSource(9)));
    }

    public function testDeletingRemovesTheUserButNotTheOneTheCallerActsAs(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $delete = new DeleteUser($this->users, $this->signOut, new InMemoryDomainEvents());

        try {
            $delete($user->id, new ManagementCaller(ClientId::fromString('dashboard'), $user->id, ScopeSet::empty()));
            self::fail('The caller deleted the account it acts as.');
        } catch (Conflict) {
            self::assertNotNull($this->users->find($user->id));
        }

        $delete($user->id, new ManagementCaller(ClientId::fromString('machine'), null, ScopeSet::empty()));
        self::assertNull($this->users->find($user->id));
    }

    // ── Connections ──────────────────────────────────────────────────────────────

    public function testAUserIsCreatedInTheDefaultPoolUnlessAnotherIsNamed(): void
    {
        $this->connections->add(Connection::pool(
            ConnectionName::fromString('staff'),
            'Staff',
            true,
            false,
            $this->clock->now(),
        ));

        $customer = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $employee = $this->create(new NewUser('ada@example.com', 'a-good-password', connection: 'staff'));

        self::assertSame('password', $customer->connection->value);
        self::assertSame('staff', $employee->connection->value);
        self::assertFalse($customer->id->equals($employee->id), 'One address, one account per pool.');
    }

    public function testAUserIsNotCreatedThroughAProviderOrAnUnknownConnection(): void
    {
        try {
            $this->create(new NewUser('ada@example.com', 'a-good-password', connection: 'google'));
            self::fail('An account was created in a social connection.');
        } catch (InvalidValue $refused) {
            self::assertStringContainsString("'google' is not one", $refused->getMessage());
        }

        $this->expectException(NotFound::class);

        $this->create(new NewUser('ada@example.com', 'a-good-password', connection: 'staff'));
    }

    public function testTheIdentitiesLinkedToAUserAreListed(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $this->link($user, 'google', 'g-1');
        $this->link($user, 'github', '42');

        self::assertSame(
            ['github', 'google'],
            array_map(
                static fn (ExternalIdentity $identity): string => $identity->provider->value,
                new ReadIdentities($this->users, $this->identities)($user->id),
            ),
        );

        $this->expectException(NotFound::class);

        new ReadIdentities($this->users, $this->identities)(UserId::generate(new SeededRandomSource(77)));
    }

    public function testAnIdentityIsUnlinkedWhenTheAccountKeepsAnotherWayIn(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $this->link($user, 'google', 'g-1');

        $this->unlink()($user->id, 'google');

        self::assertSame([], $this->identities->ofUser($user->id));
    }

    public function testTheOnlyWayIntoAnAccountIsNotUnlinked(): void
    {
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource(31)),
            'ada@example.com',
            ConnectionName::fromString('google'),
            $this->clock->now(),
        );
        $this->users->save($user);
        $this->link($user, 'google', 'g-1');
        $this->link($user, 'google', 'g-2');

        try {
            $this->unlink()($user->id, 'google');
            self::fail('The only way into the account was unlinked.');
        } catch (Conflict) {
            self::assertCount(2, $this->identities->ofUser($user->id));
        }

        // With a second provider linked, the first can go.
        $this->link($user, 'github', '42');
        $this->unlink()($user->id, 'google');
        self::assertCount(1, $this->identities->ofUser($user->id));
    }

    public function testUnlinkingWhatIsNotLinkedIsNotFound(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));

        foreach (['google', 'gitlab'] as $connection) {
            try {
                $this->unlink()($user->id, $connection);
                self::fail(sprintf("Unlinking '%s' was not refused.", $connection));
            } catch (NotFound) {
                self::assertSame([], $this->identities->ofUser($user->id));
            }
        }
    }

    public function testAPasskeyEnrolsTheAccountAndIsCounted(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $read = new ReadUsers($this->users, $this->factors, $this->passkeys);
        self::assertFalse($read->one($user->id)->mfaEnrolled);

        $this->passkeys->save($this->passkeyOf($user->id, 'one'));
        $this->passkeys->save($this->passkeyOf($user->id, 'two'));

        self::assertTrue($read->one($user->id)->mfaEnrolled);
        self::assertSame(2, $read->one($user->id)->passkeyCount);
        self::assertSame(2, $read->describeAll([$user])[0]->passkeyCount);
        self::assertTrue($read->describeAll([$user])[0]->mfaEnrolled);
    }

    public function testAnOperatorListsAndRemovesAPasskeyOfThatAccountOnly(): void
    {
        $ada = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $bob = $this->create(new NewUser('bob@example.com', 'a-good-password'));
        $adas = $this->passkeyOf($ada->id, 'ada');
        $bobs = $this->passkeyOf($bob->id, 'bob');
        $this->passkeys->save($adas);
        $this->passkeys->save($bobs);
        $events = new InMemoryDomainEvents();
        $remove = new RemoveUserPasskey($this->users, $this->passkeys, $events);

        self::assertCount(1, new ReadUserPasskeys($this->users, $this->passkeys)($ada->id));
        foreach ([$bobs->id->value, 'not-an-id', '00000000-0000-4000-8000-000000000000'] as $id) {
            try {
                $remove($ada->id, $id);
                self::fail('Removed ' . $id . ' through the wrong account.');
            } catch (NotFound) {
                self::assertCount(1, $this->passkeys->ofUser($bob->id));
            }
        }

        $remove($ada->id, $adas->id->value);

        self::assertSame([], $this->passkeys->ofUser($ada->id));
        $removed = $events->ofType(PasskeyRemoved::class);
        self::assertCount(1, $removed);
        self::assertFalse($removed[0]->byTheirOwner);
    }

    public function testThePasskeysOfAnUnknownAccountAreNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ReadUserPasskeys($this->users, $this->passkeys)(UserId::generate(new SeededRandomSource(9)));
    }

    private function passkeyOf(UserId $owner, string $seed): Passkey
    {
        return Passkey::register(
            PasskeyId::generate(new SeededRandomSource(crc32($seed))),
            $owner,
            CredentialId::fromBytes(hash('sha256', $seed, true)),
            CosePublicKey::fromBytes('k'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString($seed),
            $this->clock->now(),
        );
    }

    private function unlink(): UnlinkIdentity
    {
        return new UnlinkIdentity(
            $this->users,
            $this->identities,
            $this->connections,
            $this->transactions,
            new InMemoryDomainEvents(),
        );
    }

    private function link(User $user, string $connection, string $subject): void
    {
        $this->identities->add(ExternalIdentity::link(
            AssertedIdentity::of(ConnectionName::fromString($connection), $subject, null, false),
            $user->id,
            $this->clock->now(),
        ));
    }

    private function create(NewUser $new): User
    {
        $random = new SeededRandomSource($this->users->page(PageRequest::of())->total + 1);

        $create = new CreateUser(
            $this->users,
            $this->hasher,
            self::screen(),
            $random,
            $this->clock,
            $this->connections,
            new InMemoryDomainEvents(),
        );
        $created = $create($new);
        self::assertFalse($created->mfaEnrolled);

        return $created->user;
    }

    private function update(): UpdateUser
    {
        return new UpdateUser(
            $this->users,
            $this->hasher,
            self::screen(),
            $this->clock,
            $this->factors,
            $this->passkeys,
            $this->signOut,
            new InMemoryDomainEvents(),
        );
    }

    /** The screen every password set here passes, with one breached password known. */
    private static function screen(): PasswordScreen
    {
        return new PasswordScreen(new FakeBreachedPasswords([self::BREACHED_PASSWORD]));
    }

    private function enrol(User $user): void
    {
        $secret = TotpSecret::generate(new SeededRandomSource(4));
        $factor = MfaFactor::stage($user->id, 'sealed', $this->clock->now());
        self::assertTrue($factor->accept($secret, Totp::codeAt($secret, $this->clock->now()), $this->clock->now()));
        $factor->confirm($this->clock->now());
        $this->factors->save($factor);
    }
}
