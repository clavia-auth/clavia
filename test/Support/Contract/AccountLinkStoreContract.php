<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see AccountLinkStore} must do. Expiry is asserted by each implementation's
 * own test.
 */
trait AccountLinkStoreContract
{
    abstract protected function links(): AccountLinkStore;

    #[Test]
    public function aResetLinkIsReadBackWhole(): void
    {
        $user = self::accountForLinks('$2y$12$hash');
        $this->links()->open('token-1', AccountLink::resetPassword($user, 'login-state'), 600);

        $link = $this->links()->find('token-1');

        self::assertNotNull($link);
        self::assertSame(AccountLinkPurpose::ResetPassword, $link->purpose);
        self::assertTrue($link->userId->equals($user->id));
        self::assertSame('jane@example.com', $link->email);
        self::assertSame('login-state', $link->loginState);
        self::assertTrue($link->stillMatches($user));
    }

    #[Test]
    public function aVerificationLinkMayComeFromNoLoginPage(): void
    {
        $user = self::accountForLinks(null);
        $this->links()->open('token-1', AccountLink::verifyEmail($user, null), 600);

        $link = $this->links()->find('token-1');

        self::assertNotNull($link);
        self::assertSame(AccountLinkPurpose::VerifyEmail, $link->purpose);
        self::assertNull($link->loginState);
        self::assertNull($link->passwordFingerprint);
    }

    #[Test]
    public function findingSpendsNothingAndClaimingWorksOnce(): void
    {
        $this->links()->open('token-1', AccountLink::verifyEmail(self::accountForLinks(null), null), 600);

        self::assertNotNull($this->links()->find('token-1'));
        self::assertNotNull($this->links()->find('token-1'));
        self::assertNotNull($this->links()->claim('token-1'));
        self::assertNull($this->links()->claim('token-1'));
        self::assertNull($this->links()->find('token-1'));
    }

    #[Test]
    public function anUnknownOrEmptyTokenIsNull(): void
    {
        $this->links()->open('token-1', AccountLink::verifyEmail(self::accountForLinks(null), null), 600);

        self::assertNull($this->links()->find('token-2'));
        self::assertNull($this->links()->find(''));
        self::assertNull($this->links()->claim(''));
    }

    private static function accountForLinks(?string $passwordHash): User
    {
        return User::register(
            UserId::fromString('6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f'),
            'jane@example.com',
            $passwordHash,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
