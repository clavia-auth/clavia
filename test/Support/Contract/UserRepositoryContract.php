<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\PageRequest;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see UserRepository} must do.
 */
trait UserRepositoryContract
{
    abstract protected function users(): UserRepository;

    abstract protected function connections(): ConnectionRepository;

    #[Test]
    public function aSavedUserIsFoundByIdAndByEmail(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);

        $byId = $this->users()->find($user->id);
        $byEmail = $this->users()->findByEmail(ConnectionName::defaultPool(), 'jane@example.com');

        self::assertNotNull($byId);
        self::assertNotNull($byEmail);
        self::assertTrue($byId->id->equals($user->id));
        self::assertTrue($byEmail->id->equals($user->id));
        self::assertSame('jane@example.com', $byId->email);
        self::assertSame('$hash$', $byId->passwordHash());
        self::assertTrue($byId->isActive());
        self::assertFalse($byId->isEmailVerified());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00.123456Z'), $byId->createdAt);
        self::assertSame(0, $byId->createdAt->getOffset());
    }

    #[Test]
    public function theProfileIsSavedAndReadBackWhole(): void
    {
        $user = $this->aUser('ada@example.com');
        $this->users()->save($user);
        self::assertTrue($this->users()->find($user->id)?->profile()->equals(Profile::empty()));

        $user->changeProfile(
            Profile::of('Ada Lovelace', 'Ada', 'Lovelace', 'ada', 'https://example.com/ada.png', 'en-GB'),
            new DateTimeImmutable('2026-03-01T12:00:00Z'),
        );
        $this->users()->save($user);

        $stored = $this->users()->find($user->id);
        self::assertNotNull($stored);
        self::assertSame('Ada Lovelace', $stored->profile()->name);
        self::assertSame('Ada', $stored->profile()->givenName);
        self::assertSame('Lovelace', $stored->profile()->familyName);
        self::assertSame('ada', $stored->profile()->nickname);
        self::assertSame('https://example.com/ada.png', $stored->profile()->picture?->value);
        self::assertSame('en-GB', $stored->profile()->locale);
        self::assertEquals(new DateTimeImmutable('2026-03-01T12:00:00Z'), $stored->updatedAt());

        $stored->changeProfile(Profile::of(name: 'Ada King'), new DateTimeImmutable('2026-03-02T12:00:00Z'));
        $this->users()->save($stored);

        $cleared = $this->users()->find($user->id);
        self::assertNotNull($cleared);
        self::assertTrue($cleared->profile()->equals(Profile::of(name: 'Ada King')));
    }

    #[Test]
    public function anUnknownUserIsNull(): void
    {
        self::assertNull($this->users()->find(UserId::generate(new SeededRandomSource(99))));
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'nobody@example.com'));
    }

    #[Test]
    public function theEmailIsMatchedExactly(): void
    {
        $this->users()->save($this->aUser('jane@example.com'));

        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'Jane@example.com'));
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'jane@example.com '));
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), '%'));
    }

    #[Test]
    public function savingAgainUpdatesTheAccount(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);

        $user->deactivate(new DateTimeImmutable('2026-02-01T00:00:00Z'));
        $this->users()->save($user);

        $stored = $this->users()->find($user->id);
        self::assertNotNull($stored);
        self::assertFalse($stored->isActive());
        self::assertEquals(new DateTimeImmutable('2026-02-01T00:00:00Z'), $stored->updatedAt());
        self::assertEquals($user->createdAt, $stored->createdAt);
    }

    #[Test]
    public function aChangeIsNotStoredUntilItIsSaved(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);

        $user->deactivate(new DateTimeImmutable('2026-02-01T00:00:00Z'));

        self::assertTrue($this->users()->find($user->id)?->isActive());
    }

    #[Test]
    public function anAccountWithoutAPasswordKeepsNone(): void
    {
        $user = User::register(
            UserId::generate(new SeededRandomSource(5)),
            'sso@example.com',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users()->save($user);

        self::assertNull($this->users()->find($user->id)?->passwordHash());
    }

    #[Test]
    public function anAddressAlreadyInUseIsRefusedAsSuch(): void
    {
        $this->users()->save($this->aUser('jane@example.com'));

        $this->expectException(AlreadyExists::class);

        $this->users()->save(User::register(
            UserId::generate(new SeededRandomSource(1234)),
            'jane@example.com',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    #[Test]
    public function usersArePagedNewestFirstAndSearchedByEmail(): void
    {
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');
        foreach (['alice@clavia.dev', 'bob@clavia.dev', 'alice@other.test', '100%@x.test'] as $i => $email) {
            $this->users()->save(User::register(
                UserId::generate(new SeededRandomSource(500 + $i)),
                $email,
                null,
                $at->modify(sprintf('+%d minutes', $i)),
            ));
        }

        $first = $this->users()->page(PageRequest::of(1, 2));
        self::assertSame(4, $first->total);
        self::assertSame(
            ['100%@x.test', 'alice@other.test'],
            array_map(static fn (User $u): string => $u->email, $first->items),
        );
        self::assertSame(2, $this->users()->page(PageRequest::of(search: 'ALICE'))->total);
        self::assertSame(1, $this->users()->page(PageRequest::of(search: '100%'))->total);
        self::assertSame([], $this->users()->page(PageRequest::of(3, 2))->items);
    }

    #[Test]
    public function aDeletedUserIsGone(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);

        $this->users()->delete($user->id);

        self::assertNull($this->users()->find($user->id));
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'jane@example.com'));
    }

    #[Test]
    public function addressesAreMatchedIgnoringCaseOnlyWhenAsked(): void
    {
        $this->users()->save($this->aUser('Ada@Example.com'));
        $this->users()->save($this->aUser('ada@example.com'));
        $this->users()->save($this->aUser('bob@example.com'));

        $matches = array_map(
            static fn (User $user): string => $user->email,
            $this->users()->matchingEmail('ADA@example.COM', [ConnectionName::defaultPool()]),
        );
        sort($matches);

        self::assertSame(['Ada@Example.com', 'ada@example.com'], $matches);
        self::assertSame([], $this->users()->matchingEmail('ada@example.co', [ConnectionName::defaultPool()]));
        self::assertSame([], $this->users()->matchingEmail('%@example.com', [ConnectionName::defaultPool()]));
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'ADA@example.com'));
    }

    #[Test]
    public function anAddressIsOneAccountPerPool(): void
    {
        $staff = ConnectionName::fromString('staff');
        $this->connections()->add(
            Connection::pool($staff, 'Staff', true, false, new DateTimeImmutable('2026-01-15T10:00:00Z')),
        );
        $customer = $this->aUser('jane@example.com');
        $employee = User::register(
            UserId::generate(new SeededRandomSource(99)),
            'jane@example.com',
            '$hash$',
            new DateTimeImmutable('2026-01-16T10:00:00Z'),
            $staff,
        );
        $this->users()->save($customer);
        $this->users()->save($employee);

        self::assertSame('password', $this->users()->find($customer->id)?->connection->value);
        self::assertSame('staff', $this->users()->find($employee->id)?->connection->value);
        self::assertTrue(
            $this->users()->findByEmail($staff, 'jane@example.com')?->id->equals($employee->id),
        );
        self::assertTrue(
            $this->users()->findByEmail(ConnectionName::defaultPool(), 'jane@example.com')?->id->equals($customer->id),
        );
        self::assertCount(1, $this->users()->matchingEmail('jane@example.com', [$staff]));
        self::assertSame(
            [$customer->id->value, $employee->id->value],
            array_map(
                static fn (User $user): string => $user->id->value,
                $this->users()->matchingEmail('JANE@example.com', [ConnectionName::defaultPool(), $staff]),
            ),
        );
        self::assertSame([], $this->users()->matchingEmail('jane@example.com', []));
        self::assertSame(1, $this->users()->countIn($staff));
        self::assertSame(0, $this->users()->countIn(ConnectionName::fromString('google')));
    }

    #[Test]
    public function anAccountAProviderCreatedBelongsToItsConnection(): void
    {
        $google = ConnectionName::fromString('google');
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource(7)),
            'ada@example.com',
            $google,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users()->save($user);

        $read = $this->users()->find($user->id);

        self::assertNotNull($read);
        self::assertSame('google', $read->connection->value);
        self::assertNull($read->passwordHash());
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'ada@example.com'));
        self::assertSame(1, $this->users()->countIn($google));
    }

    #[Test]
    public function aChangedAddressIsStored(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);
        $user->changeEmail('janet@example.com', new DateTimeImmutable('2026-01-16T10:00:00Z'));
        $this->users()->save($user);

        self::assertSame('janet@example.com', $this->users()->find($user->id)?->email);
        self::assertNull($this->users()->findByEmail(ConnectionName::defaultPool(), 'jane@example.com'));
    }

    #[Test]
    public function theAccountsOfAConnectionAreWalkedByIdAPageAtATime(): void
    {
        $emails = ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com', 'e@example.com'];
        foreach ($emails as $email) {
            $this->users()->save($this->aUser($email));
        }
        $this->users()->save(User::registerFromProvider(
            UserId::generate(new SeededRandomSource(99)),
            'a@example.com',
            ConnectionName::fromString('google'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $seen = [];
        $after = null;
        do {
            $page = $this->users()->inConnection(ConnectionName::defaultPool(), $after, 2);
            self::assertLessThanOrEqual(2, count($page));
            foreach ($page as $user) {
                $seen[] = $user->id->value;
                $after = $user->id;
            }
        } while ($page !== []);

        $sorted = $seen;
        sort($sorted);
        self::assertSame($sorted, $seen, 'By id.');
        self::assertCount(5, $seen, 'Each account of the pool once, and none of another connection.');
    }

    #[Test]
    public function theApplicationMetadataIsSavedAndReadBackWhole(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);
        self::assertTrue($this->users()->find($user->id)?->appMetadata()->isEmpty());

        $metadata = AppMetadata::fromJson('{"tenant":{"region":"eu","id":42},"plan":"pro","flags":[],"extra":{}}');
        $user->changeAppMetadata($metadata, new DateTimeImmutable('2026-01-16T10:00:00Z'));
        $this->users()->save($user);

        $read = $this->users()->find($user->id);
        self::assertNotNull($read);
        self::assertTrue($read->appMetadata()->equals($metadata), $read->appMetadata()->toJson());
        self::assertSame($metadata->toJson(), $read->appMetadata()->toJson());
    }

    private function aUser(string $email): User
    {
        return User::register(
            UserId::generate(new SeededRandomSource(crc32($email))),
            $email,
            '$hash$',
            new DateTimeImmutable('2026-01-15T10:00:00.123456Z'),
        );
    }
}
