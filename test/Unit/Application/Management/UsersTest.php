<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\Caller\ManagementCaller;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\NewUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\UpdateUser;
use Clavia\Application\Management\Users\UserChanges;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

/**
 * Creating, changing, reading and deleting end users through the Management API's use cases.
 */
final class UsersTest extends TestCase
{
    private InMemoryUserRepository $users;
    private FakePasswordHasher $hasher;
    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->hasher = new FakePasswordHasher();
        $this->clock = new FrozenClock();
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

    public function testAnAddressAlreadyUsedIsRefusedAsSuch(): void
    {
        $this->create(new NewUser('ada@example.com', 'a-good-password'));

        $this->expectException(AlreadyExists::class);

        $this->create(new NewUser('ada@example.com', 'another-password'));
    }

    public function testAnUpdateChangesOnlyWhatItNames(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', profile: ['name' => 'Ada']));

        $updated = $this->update()($user->id, new UserChanges(profile: ['nickname' => 'ada']));

        self::assertSame('ada@example.com', $updated->email);
        self::assertSame('Ada', $updated->profile()->name);
        self::assertSame('ada', $updated->profile()->nickname);
        self::assertTrue($this->hasher->verify('a-good-password', (string) $updated->passwordHash()));
    }

    public function testAProfileFieldSetToNullIsCleared(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', profile: ['name' => 'Ada']));

        self::assertNull($this->update()($user->id, new UserChanges(profile: ['name' => null]))->profile()->name);
    }

    public function testANewAddressIsUnverifiedUnlessTheSameChangeSaysOtherwise(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password', emailVerified: true));

        self::assertFalse($this->update()($user->id, new UserChanges(email: 'ada@new.example'))->isEmailVerified());
        self::assertTrue(
            $this->update()($user->id, new UserChanges(email: 'ada@other.example', emailVerified: true))
                ->isEmailVerified(),
        );
    }

    public function testAPasswordChangeIsHashedAndChecked(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));

        $updated = $this->update()($user->id, new UserChanges(password: 'another-password'));
        self::assertTrue($this->hasher->verify('another-password', (string) $updated->passwordHash()));

        $this->expectException(InvalidValue::class);
        $this->update()($user->id, new UserChanges(password: str_repeat('a', 73)));
    }

    public function testDeactivatingAndReactivating(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));

        self::assertFalse($this->update()($user->id, new UserChanges(isActive: false))->isActive());
        self::assertTrue($this->update()($user->id, new UserChanges(isActive: true))->isActive());
    }

    public function testAnUnknownUserIsNotFound(): void
    {
        $this->expectException(NotFound::class);

        new ReadUsers($this->users)->one(UserId::generate(new SeededRandomSource(9)));
    }

    public function testDeletingRemovesTheUserButNotTheOneTheCallerActsAs(): void
    {
        $user = $this->create(new NewUser('ada@example.com', 'a-good-password'));
        $delete = new DeleteUser($this->users);

        try {
            $delete($user->id, new ManagementCaller(ClientId::fromString('dashboard'), $user->id, ScopeSet::empty()));
            self::fail('The caller deleted the account it acts as.');
        } catch (Conflict) {
            self::assertNotNull($this->users->find($user->id));
        }

        $delete($user->id, new ManagementCaller(ClientId::fromString('machine'), null, ScopeSet::empty()));
        self::assertNull($this->users->find($user->id));
    }

    private function create(NewUser $new): User
    {
        $random = new SeededRandomSource($this->users->page(PageRequest::of())->total + 1);

        return new CreateUser($this->users, $this->hasher, $random, $this->clock)($new);
    }

    private function update(): UpdateUser
    {
        return new UpdateUser($this->users, $this->hasher, $this->clock);
    }
}
