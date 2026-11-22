<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Identity;

use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class AccountLinkTest extends TestCase
{
    private DateTimeImmutable $now;

    #[\Override]
    protected function setUp(): void
    {
        $this->now = new DateTimeImmutable('2026-11-22T10:00:00Z');
    }

    public function testAVerificationLinkAnswersForItsAccountAtItsAddress(): void
    {
        $user = $this->user();
        $link = AccountLink::verifyEmail($user, 'login-state');

        self::assertSame(AccountLinkPurpose::VerifyEmail, $link->purpose);
        self::assertSame('login-state', $link->loginState);
        self::assertNull($link->passwordFingerprint);
        self::assertTrue($link->stillMatches($user));
    }

    public function testALinkDiesWhenTheAddressChanges(): void
    {
        $user = $this->user();
        $link = AccountLink::verifyEmail($user, null);

        $user->changeEmail('someone.else@example.com', $this->now);

        self::assertFalse($link->stillMatches($user));
    }

    public function testTheAddressIsComparedWithoutCase(): void
    {
        $user = $this->user();
        $link = AccountLink::verifyEmail($user, null);

        $user->changeEmail('JANE@example.com', $this->now);

        self::assertTrue($link->stillMatches($user));
    }

    public function testALinkDiesWhenTheAccountIsDeactivatedOrIsAnother(): void
    {
        $user = $this->user();
        $link = AccountLink::verifyEmail($user, null);
        $other = User::register(
            UserId::fromString('11111111-2222-4333-8444-555555555555'),
            'jane@example.com',
            null,
            $this->now,
        );

        self::assertFalse($link->stillMatches($other));
        $user->deactivate($this->now);
        self::assertFalse($link->stillMatches($user));
    }

    public function testAResetLinkDiesOnceThePasswordChanges(): void
    {
        $user = $this->user('$2y$12$old');
        $link = AccountLink::resetPassword($user, null);
        self::assertTrue($link->stillMatches($user));

        $user->changePassword('$2y$12$new', $this->now);

        self::assertFalse($link->stillMatches($user));
    }

    public function testAResetLinkWorksForAnAccountWithoutAPassword(): void
    {
        $user = $this->user(null);

        self::assertTrue(AccountLink::resetPassword($user, null)->stillMatches($user));
    }

    public function testTheFingerprintGivesNothingOfTheHashAway(): void
    {
        $link = AccountLink::resetPassword($this->user('$2y$12$secret-hash'), null);

        self::assertStringNotContainsString('secret-hash', (string) $link->passwordFingerprint?->toString());
    }

    private function user(?string $passwordHash = '$2y$12$hash'): User
    {
        return User::register(
            UserId::fromString('6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f'),
            'jane@example.com',
            $passwordHash,
            $this->now,
        );
    }
}
