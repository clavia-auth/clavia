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
use Clavia\Application\Authentication\LoginPage\LoginPage;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FakeIdentityProvider;
use ClaviaTest\Support\Fake\FakeIdentityProviders;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConnectionRepository;
use ClaviaTest\Support\Fake\InMemoryLoginStateStore;
use ClaviaTest\Support\Fake\InMemorySessionStore;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\RecordingMailer;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class DescribeLoginPageTest extends TestCase
{
    private InMemoryLoginStateStore $loginStates;
    private Sessions $sessions;
    private DescribeLoginPage $describe;
    private User $user;
    private InMemoryClientRepository $clients;
    private InMemoryConnectionRepository $connections;
    private RecordingMailer $mailer;

    #[\Override]
    protected function setUp(): void
    {
        $clock = new FrozenClock();
        $this->mailer = new RecordingMailer();
        $users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->connections = new InMemoryConnectionRepository($this->clients);
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
        $this->clients->save(Clients::public(
            'spa',
            ['https://app.example/cb', 'https://app.example/other', 'http://localhost:3000/cb'],
        ));

        $this->describe = new DescribeLoginPage(
            $this->loginStates,
            $this->clients,
            new ResolveEndUser($this->sessions, $users, new DevelopmentAutoLogin($users, null, true)),
            $users,
            new ConnectionAccess(
                $this->connections,
                new FakeIdentityProviders(new FakeIdentityProvider('google'), new FakeIdentityProvider('github')),
                $this->mailer,
            ),
        );
    }

    public function testAnAnonymousVisitorWithNothingPendingGetsTheFormAndOnlyThisServer(): void
    {
        $page = ($this->describe)(null, null);

        self::assertNull($page->signedInAs);
        self::assertSame([], $page->formOrigins);
        self::assertTrue($page->methods->password);
    }

    public function testWithNothingPendingEveryUsableConnectionIsOffered(): void
    {
        self::assertSame([['github', 'GitHub'], ['google', 'Google']], self::offered(($this->describe)(null, null)));
    }

    public function testAPendingRequestOffersOnlyWhatItsApplicationEnables(): void
    {
        $this->clients->save(Clients::public('spa')->withConnections([ConnectionName::fromString('google')]));
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        $page = ($this->describe)('handle', null);

        self::assertFalse($page->methods->password);
        self::assertFalse($page->methods->email);
        self::assertSame([['google', 'Google']], self::offered($page));
    }

    public function testTheEmailFormIsOfferedWhenTheApplicationEnablesItAndMailCanBeSent(): void
    {
        $this->clients->save(Clients::public('spa')->withConnections([ConnectionName::email()]));
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));

        $page = ($this->describe)('handle', null);

        self::assertTrue($page->methods->email);
        self::assertFalse($page->methods->password);
        self::assertSame([], self::offered($page));
        self::assertFalse($page->methods->isEmpty());
        self::assertTrue(($this->describe)(null, null)->methods->email, 'Usable, so offered without a request.');
    }

    public function testAConnectionSwitchedOffOrWithoutAWorkingProviderIsNotOffered(): void
    {
        $google = $this->connections->find(ConnectionName::fromString('google'));
        self::assertNotNull($google);
        $this->connections->save($google->switched(false, null, null));
        $this->connections->add(Connection::pool(
            ConnectionName::fromString('staff'),
            'Staff',
            true,
            true,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $page = ($this->describe)(null, null);

        self::assertSame([['github', 'GitHub']], self::offered($page));
        self::assertTrue($page->methods->password);
    }

    public function testAnApplicationWithNothingUsableHasNoWayIn(): void
    {
        $this->clients->save(Clients::public('spa')->withConnections([]));
        $this->loginStates->put('handle', new LoginState('/oauth2/authorize?x=y', ClientId::fromString('spa')));
        $pool = $this->connections->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        $this->connections->save($pool->switched(null, false, null));

        self::assertTrue(($this->describe)('handle', null)->methods->isEmpty());
    }

    public function testAThirdPartyApplicationIsOfferedTheDomainConnectionsOnly(): void
    {
        $this->clients->save(Clients::public('tpc_aaaaaaaaaaaaaaaaaaaaaa'));
        $this->loginStates->put(
            'handle',
            new LoginState('/oauth2/authorize?x=y', ClientId::fromString('tpc_aaaaaaaaaaaaaaaaaaaaaa')),
        );

        $page = ($this->describe)('handle', null);

        self::assertTrue($page->methods->password);
        self::assertFalse($page->methods->email, 'Not a domain connection.');
        self::assertSame([], self::offered($page));
    }

    public function testASignedInVisitorWithNothingPendingIsToldWhoTheyAre(): void
    {
        $sessionId = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );

        self::assertSame('jane@example.com', ($this->describe)(null, $sessionId)->signedInAs);
        self::assertSame('jane@example.com', ($this->describe)('', $sessionId)->signedInAs);
        self::assertTrue(($this->describe)(null, $sessionId)->methods->isEmpty(), 'No form, so nothing to offer.');
    }

    public function testAPendingRequestShowsTheFormEvenToASignedInVisitorAndNamesTheApplicationsOrigins(): void
    {
        $sessionId = $this->sessions->establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            ConnectionName::defaultPool(),
            null,
        );
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

    /** @return list<array{string, string}> */
    private static function offered(LoginPage $page): array
    {
        return array_map(
            static fn (ExternalProviderOption $option): array => [$option->name, $option->label],
            $page->methods->providers,
        );
    }
}
