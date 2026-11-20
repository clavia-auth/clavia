<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

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

    #[Test]
    public function aSavedUserIsFoundByIdAndByEmail(): void
    {
        $user = $this->aUser('jane@example.com');
        $this->users()->save($user);

        $byId = $this->users()->find($user->id);
        $byEmail = $this->users()->findByEmail('jane@example.com');

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
        self::assertNull($this->users()->findByEmail('nobody@example.com'));
    }

    #[Test]
    public function theEmailIsMatchedExactly(): void
    {
        $this->users()->save($this->aUser('jane@example.com'));

        self::assertNull($this->users()->findByEmail('Jane@example.com'));
        self::assertNull($this->users()->findByEmail('jane@example.com '));
        self::assertNull($this->users()->findByEmail('%'));
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
        self::assertNull($this->users()->findByEmail('jane@example.com'));
    }

    #[Test]
    public function addressesAreMatchedIgnoringCaseOnlyWhenAsked(): void
    {
        $this->users()->save($this->aUser('Ada@Example.com'));
        $this->users()->save($this->aUser('ada@example.com'));
        $this->users()->save($this->aUser('bob@example.com'));

        $matches = array_map(
            static fn (User $user): string => $user->email,
            $this->users()->matchingEmail('ADA@example.COM'),
        );
        sort($matches);

        self::assertSame(['Ada@Example.com', 'ada@example.com'], $matches);
        self::assertSame([], $this->users()->matchingEmail('ada@example.co'));
        self::assertSame([], $this->users()->matchingEmail('%@example.com'));
        self::assertNull($this->users()->findByEmail('ADA@example.com'));
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
