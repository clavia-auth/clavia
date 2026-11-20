<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ExternalIdentityTest extends TestCase
{
    #[DataProvider('providerNames')]
    public function testAProviderNameIsASlug(string $name, bool $valid): void
    {
        if (! $valid) {
            $this->expectException(InvalidValue::class);
        }

        self::assertSame($name, ProviderName::fromString($name)->value);
    }

    /** @return iterable<string, array{string, bool}> */
    public static function providerNames(): iterable
    {
        yield 'google' => ['google', true];
        yield 'with a dash and a digit' => ['acme-sso2', true];
        yield 'thirty-two characters' => [str_repeat('a', 32), true];
        yield 'empty' => ['', false];
        yield 'capitals' => ['Google', false];
        yield 'a leading digit' => ['2fa', false];
        yield 'a slash' => ['google/x', false];
        yield 'a trailing newline' => ["google\n", false];
        yield 'thirty-three characters' => [str_repeat('a', 33), false];
    }

    public function testAnAddressCountsOnlyWhenTheProviderVouchesForIt(): void
    {
        $google = ProviderName::fromString('google');

        $trimmed = AssertedIdentity::of($google, 's', ' ada@example.com ', true);
        self::assertSame('ada@example.com', $trimmed->verifiedEmail());
        self::assertNull(AssertedIdentity::of($google, 's', 'ada@example.com', false)->verifiedEmail());
        self::assertSame('ada@example.com', AssertedIdentity::of($google, 's', 'ada@example.com', false)->email);
        // No address cannot be a verified one, whatever the provider claims.
        self::assertFalse(AssertedIdentity::of($google, 's', null, true)->emailVerified);
        self::assertNull(AssertedIdentity::of($google, 's', '  ', true)->email);
    }

    #[DataProvider('unusableSubjects')]
    public function testASubjectThatCannotBeStoredIsRefused(string $subject): void
    {
        $this->expectException(InvalidValue::class);

        AssertedIdentity::of(ProviderName::fromString('google'), $subject, null, false);
    }

    /** @return iterable<string, array{string}> */
    public static function unusableSubjects(): iterable
    {
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('1', AssertedIdentity::MAX_SUBJECT_LENGTH + 1)];
        yield 'a control character' => ["123\x00"];
        yield 'a newline' => ["123\n"];
    }

    public function testALinkKeepsWhatTheProviderReportedAndTheAccountItPointsAt(): void
    {
        $userId = UserId::generate(new SeededRandomSource());
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');

        $identity = ExternalIdentity::link(
            AssertedIdentity::of(ProviderName::fromString('github'), '4242', 'me@example.com', true),
            $userId,
            $now,
        );

        self::assertSame('github', $identity->provider->value);
        self::assertSame('4242', $identity->subject);
        self::assertTrue($identity->userId->equals($userId));
        self::assertSame('me@example.com', $identity->email);
        self::assertSame($now, $identity->linkedAt);
    }

    public function testAnAccountAProviderVouchedForHasNoPasswordAndAVerifiedAddress(): void
    {
        $user = User::registerFromProvider(
            UserId::generate(new SeededRandomSource()),
            'ada@example.com',
            new DateTimeImmutable(),
        );

        self::assertNull($user->passwordHash());
        self::assertTrue($user->isEmailVerified());
        self::assertTrue($user->isActive());

        $this->expectException(InvalidValue::class);
        User::registerFromProvider(
            UserId::generate(new SeededRandomSource()),
            'not an address',
            new DateTimeImmutable(),
        );
    }
}
