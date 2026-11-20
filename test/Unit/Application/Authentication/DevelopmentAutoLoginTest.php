<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\DevelopmentAutoLogin;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

final class DevelopmentAutoLoginTest extends TestCase
{
    private InMemoryUserRepository $users;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(1)),
            'dev@clavia.test',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users->save($this->user);
    }

    public function testNobodyIsSignedInWhenItIsNotConfigured(): void
    {
        self::assertNull(new DevelopmentAutoLogin($this->users, null, true)->endUser());
        self::assertNull(new DevelopmentAutoLogin($this->users, '', true)->endUser());
    }

    public function testTheConfiguredUserIsSignedInInDevelopment(): void
    {
        $endUser = new DevelopmentAutoLogin($this->users, 'dev@clavia.test', true)->endUser();

        self::assertTrue($endUser?->userId->equals($this->user->id));
    }

    public function testAnUnknownAddressSignsNobodyIn(): void
    {
        self::assertNull(new DevelopmentAutoLogin($this->users, 'nobody@clavia.test', true)->endUser());
    }

    public function testADeactivatedAccountIsNotSignedIn(): void
    {
        $this->user->deactivate(new DateTimeImmutable('2026-01-16T00:00:00Z'));
        $this->users->save($this->user);

        self::assertNull(new DevelopmentAutoLogin($this->users, 'dev@clavia.test', true)->endUser());
    }

    public function testItRefusesToRunOutsideDevelopment(): void
    {
        // Settings already refuse this combination at boot; this is the second lock on
        // a door that signs anyone in without a password.
        $autoLogin = new DevelopmentAutoLogin($this->users, 'dev@clavia.test', false);

        $this->expectException(LogicException::class);

        $autoLogin->endUser();
    }

    public function testOutsideDevelopmentItIsSilentWhenNotConfigured(): void
    {
        self::assertNull(new DevelopmentAutoLogin($this->users, null, false)->endUser());
    }
}
