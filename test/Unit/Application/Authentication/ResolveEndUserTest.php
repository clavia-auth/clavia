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
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class ResolveEndUserTest extends TestCase
{
    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private Sessions $sessions;
    private User $user;
    private User $developer;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->users = new InMemoryUserRepository();
        $this->sessions = new Sessions(
            new InMemorySessionStore($this->clock),
            new SecretGenerator(new SeededRandomSource(1)),
            $this->clock,
            28800,
            604800,
            new InMemoryDomainEvents(),
        );
        $now = $this->clock->now();
        $this->user = User::register(UserId::generate(new SeededRandomSource(2)), 'jane@example.com', null, $now);
        $this->developer = User::register(UserId::generate(new SeededRandomSource(3)), 'dev@clavia.test', null, $now);
        $this->users->save($this->user);
        $this->users->save($this->developer);
    }

    public function testTheSessionSaysWhoItIs(): void
    {
        $sessionId = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        $endUser = $this->resolver()($sessionId);

        self::assertNotNull($endUser);
        self::assertTrue($endUser->userId->equals($this->user->id));
        self::assertSame([AuthenticationMethod::Password], $endUser->session?->methods);
    }

    public function testWithoutASessionNobodyIsSignedIn(): void
    {
        self::assertNull($this->resolver()(null));
        self::assertNull($this->resolver()('never-issued'));
    }

    public function testAnAccountDeactivatedSinceSignInIsNobody(): void
    {
        $sessionId = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $this->user->deactivate($this->clock->now());
        $this->users->save($this->user);

        self::assertNull($this->resolver()($sessionId));
    }

    public function testTheDevelopmentAutoLoginIsOnlyConsultedWithoutASignedInUser(): void
    {
        $sessionId = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
        $resolve = $this->resolver('dev@clavia.test');

        self::assertTrue($resolve($sessionId)?->userId->equals($this->user->id));

        $autoLoggedIn = $resolve(null);
        self::assertNotNull($autoLoggedIn);
        self::assertTrue($autoLoggedIn->userId->equals($this->developer->id));
        // Nobody actually authenticated: there is no session to report when or how.
        self::assertNull($autoLoggedIn->session);
    }

    private function resolver(?string $autoLoginEmail = null): ResolveEndUser
    {
        return new ResolveEndUser(
            $this->sessions,
            $this->users,
            new DevelopmentAutoLogin($this->users, $autoLoginEmail, true),
        );
    }
}
