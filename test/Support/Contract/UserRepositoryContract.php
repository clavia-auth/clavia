<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
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
