<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UserTest extends TestCase
{
    public function testANewAccountIsActiveAndItsEmailUnverified(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');

        $user = User::register($this->id(), 'jane@example.com', '$hash$', $now);

        self::assertTrue($user->isActive());
        self::assertFalse($user->isEmailVerified());
        self::assertSame('jane@example.com', $user->email);
        self::assertSame('$hash$', $user->passwordHash());
        self::assertSame($now, $user->createdAt);
        self::assertSame($now, $user->updatedAt());
    }

    public function testTheEmailIsKeptExactlyAsGiven(): void
    {
        // No case folding: whether two spellings are one mailbox is the mail server's
        // call, and the address is not the account's identity anyway.
        $user = User::register($this->id(), 'Jane.Doe+tag@Example.COM', null, new DateTimeImmutable());

        self::assertSame('Jane.Doe+tag@Example.COM', $user->email);
    }

    public function testAnEmptyHashIsNoPasswordRatherThanAnEmptyOne(): void
    {
        self::assertNull(User::register($this->id(), 'sso@example.com', '', new DateTimeImmutable())->passwordHash());
        self::assertNull(User::register($this->id(), 'sso@example.com', null, new DateTimeImmutable())->passwordHash());
    }

    #[DataProvider('notAnAddress')]
    public function testAnythingButAnAddressIsRefused(string $email): void
    {
        $this->expectException(InvalidValue::class);

        User::register($this->id(), $email, null, new DateTimeImmutable());
    }

    /** @return iterable<string, array{string}> */
    public static function notAnAddress(): iterable
    {
        yield 'empty' => [''];
        yield 'no at sign' => ['jane.example.com'];
        yield 'two at signs' => ['jane@doe@example.com'];
        yield 'no local part' => ['@example.com'];
        yield 'no domain' => ['jane@'];
        yield 'inner space' => ['jane doe@example.com'];
        yield 'trailing newline' => ["jane@example.com\n"];
        yield 'too long' => [str_repeat('a', 310) . '@example.com'];
    }

    public function testTheSameRulesApplyWhenReadBackFromStorage(): void
    {
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');

        $this->expectException(InvalidValue::class);

        User::reconstitute($this->id(), 'not an address', null, false, true, Profile::empty(), $at, $at);
    }

    public function testDeactivatingAndReactivatingRecordsWhen(): void
    {
        $user = User::register($this->id(), 'jane@example.com', null, new DateTimeImmutable('2026-01-15T10:00:00Z'));
        $later = new DateTimeImmutable('2026-02-01T00:00:00Z');
        $evenLater = new DateTimeImmutable('2026-03-01T00:00:00Z');

        $user->deactivate($later);
        self::assertFalse($user->isActive());
        self::assertSame($later, $user->updatedAt());

        $user->activate($evenLater);
        self::assertTrue($user->isActive());
        self::assertSame($evenLater, $user->updatedAt());
    }

    public function testAChangeThatChangesNothingIsNotAnUpdate(): void
    {
        $created = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $user = User::register($this->id(), 'jane@example.com', null, $created);

        $user->activate(new DateTimeImmutable('2026-02-01T00:00:00Z'));

        self::assertSame($created, $user->updatedAt());
    }

    public function testChangingTheProfileMovesUpdatedAtOnlyWhenSomethingChanged(): void
    {
        $user = User::register($this->id(), 'ada@example.com', null, new DateTimeImmutable('2026-01-01T00:00:00Z'));

        $user->changeProfile(Profile::empty(), new DateTimeImmutable('2026-01-02T00:00:00Z'));
        self::assertEquals(new DateTimeImmutable('2026-01-01T00:00:00Z'), $user->updatedAt());

        $user->changeProfile(Profile::of(name: 'Ada'), new DateTimeImmutable('2026-01-03T00:00:00Z'));
        self::assertSame('Ada', $user->profile()->name);
        self::assertEquals(new DateTimeImmutable('2026-01-03T00:00:00Z'), $user->updatedAt());

        $user->changeProfile(Profile::of(name: 'Ada'), new DateTimeImmutable('2026-01-04T00:00:00Z'));
        self::assertEquals(new DateTimeImmutable('2026-01-03T00:00:00Z'), $user->updatedAt());
    }

    public function testANewAddressIsUnverifiedAndTheSameAddressChangesNothing(): void
    {
        $created = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $user = User::register($this->id(), 'ada@example.com', null, $created);
        $user->recordEmailVerification(true, new DateTimeImmutable('2026-01-02T00:00:00Z'));
        self::assertTrue($user->isEmailVerified());

        $user->changeEmail('ada@example.com', new DateTimeImmutable('2026-01-03T00:00:00Z'));
        self::assertTrue($user->isEmailVerified());
        self::assertEquals(new DateTimeImmutable('2026-01-02T00:00:00Z'), $user->updatedAt());

        $user->changeEmail('ada@elsewhere.example', new DateTimeImmutable('2026-01-04T00:00:00Z'));
        self::assertSame('ada@elsewhere.example', $user->email);
        self::assertFalse($user->isEmailVerified());
        self::assertEquals(new DateTimeImmutable('2026-01-04T00:00:00Z'), $user->updatedAt());
    }

    public function testANewAddressFollowsTheSameRules(): void
    {
        $user = User::register($this->id(), 'ada@example.com', null, new DateTimeImmutable());

        $this->expectException(InvalidValue::class);

        $user->changeEmail('not-an-address', new DateTimeImmutable());
    }

    public function testRecordingTheSameVerificationIsNotAnUpdate(): void
    {
        $created = new DateTimeImmutable('2026-01-01T00:00:00Z');
        $user = User::register($this->id(), 'ada@example.com', null, $created);

        $user->recordEmailVerification(false, new DateTimeImmutable('2026-01-02T00:00:00Z'));

        self::assertSame($created, $user->updatedAt());
    }

    public function testChangingThePasswordReplacesTheHash(): void
    {
        $user = User::register($this->id(), 'ada@example.com', null, new DateTimeImmutable('2026-01-01T00:00:00Z'));

        $user->changePassword('$2y$12$hash', new DateTimeImmutable('2026-01-02T00:00:00Z'));

        self::assertSame('$2y$12$hash', $user->passwordHash());
        self::assertEquals(new DateTimeImmutable('2026-01-02T00:00:00Z'), $user->updatedAt());
    }

    private function id(): UserId
    {
        return UserId::generate(new SeededRandomSource(1));
    }
}
