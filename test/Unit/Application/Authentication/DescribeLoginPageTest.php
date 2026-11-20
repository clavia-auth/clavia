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
use Clavia\Application\Authentication\External\ExternalProviderOption;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProvider;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class DescribeLoginPageTest extends TestCase
{
    private InMemoryLoginStateStore $loginStates;
    private Sessions $sessions;
    private DescribeLoginPage $describe;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $clock = new FrozenClock();
        $users = new InMemoryUserRepository();
        $clients = new InMemoryClientRepository();
        $this->loginStates = new InMemoryLoginStateStore($clock);
        $this->sessions = new Sessions(
            new InMemorySessionStore($clock),
            new SecretGenerator(new SeededRandomSource(1)),
            $clock,
            28800,
            604800,
        );
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(2)),
            'jane@example.com',
            null,
            $clock->now(),
        );
        $users->save($this->user);
        $clients->save(Clients::public(
            'spa',
            ['https://app.example/cb', 'https://app.example/other', 'http://localhost:3000/cb'],
        ));

        $this->describe = new DescribeLoginPage(
            $this->loginStates,
            $clients,
            new ResolveEndUser($this->sessions, $users, new DevelopmentAutoLogin($users, null, true)),
            $users,
            new FakeIdentityProviders(
                new FakeIdentityProvider('google', 'Google'),
                new FakeIdentityProvider('github', 'GitHub'),
            ),
        );
    }

    public function testAnAnonymousVisitorWithNothingPendingGetsTheFormAndOnlyThisServer(): void
    {
        $page = ($this->describe)(null, null);

        self::assertNull($page->signedInAs);
        self::assertSame([], $page->formOrigins);
    }

    public function testTheFormOffersEveryConfiguredProviderInOrder(): void
    {
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        foreach ([($this->describe)(null, null), ($this->describe)('handle', null)] as $page) {
            self::assertSame(
                [['google', 'Google'], ['github', 'GitHub']],
                array_map(
                    static fn (ExternalProviderOption $option): array => [$option->name, $option->label],
                    $page->providers,
                ),
            );
        }
    }

    public function testASignedInVisitorWithNothingPendingIsToldWhoTheyAre(): void
    {
        $sessionId = $this->sessions->establish($this->user->id, [AuthenticationMethod::Password], null);

        self::assertSame('jane@example.com', ($this->describe)(null, $sessionId)->signedInAs);
        self::assertSame('jane@example.com', ($this->describe)('', $sessionId)->signedInAs);
        self::assertSame([], ($this->describe)(null, $sessionId)->providers, 'No form, so nothing to offer.');
    }

    public function testAPendingRequestShowsTheFormEvenToASignedInVisitorAndNamesTheApplicationsOrigins(): void
    {
        $sessionId = $this->sessions->establish($this->user->id, [AuthenticationMethod::Password], null);
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        $page = ($this->describe)('handle', $sessionId);

        self::assertNull($page->signedInAs);
        self::assertSame(['https://app.example', 'http://localhost:3000'], $page->formOrigins);
    }

    public function testAHandleThatNamesNothingAddsNoOrigin(): void
    {
        $this->loginStates->put('no-client', new LoginState('/somewhere'));
        $this->loginStates->put('gone-client', new LoginState('/somewhere', ClientId::fromString('deleted')));

        self::assertSame([], $this->describe->formOrigins('unknown'));
        self::assertSame([], $this->describe->formOrigins('no-client'));
        self::assertSame([], $this->describe->formOrigins('gone-client'));
        self::assertSame([], $this->describe->formOrigins(null));
    }
}
