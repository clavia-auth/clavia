<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Application\OAuth2\Consent\ConsentGiven;
use Clavia\Application\OAuth2\Consent\DecideConsent;
use Clavia\Application\OAuth2\Consent\DescribeConsent;
use Clavia\Application\OAuth2\Consent\HeldConsents;
use Clavia\Application\OAuth2\Consent\ScopeLine;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryConsentRepository;
use ClaviaTest\Support\Fake\InMemoryConsentStateStore;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use PHPUnit\Framework\TestCase;

/**
 * The consent screen's two use cases: what it shows, and what an answer does.
 */
final class ConsentScreenTest extends TestCase
{
    private const string HANDLE = 'the-handle';
    private const string RESUME_AT = '/oauth2/authorize?client_id=tpc_partner&scope=openid%20email%20invoices%3Aread';

    private FrozenClock $clock;
    private InMemoryConsentStateStore $states;
    private InMemoryConsentRepository $consents;
    private InMemoryResourceServerRepository $resourceServers;
    private DescribeConsent $describe;
    private DecideConsent $decide;
    private EndUser $jane;
    private ResourceServer $api;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $users = new InMemoryUserRepository();
        $clients = new InMemoryClientRepository();
        $this->resourceServers = new InMemoryResourceServerRepository();
        $this->states = new InMemoryConsentStateStore($this->clock);
        $this->consents = new InMemoryConsentRepository($users, $clients, $this->resourceServers);
        $held = new HeldConsents($this->states, $users, $clients, $this->resourceServers);
        $this->describe = new DescribeConsent($held, ScopeSet::fromString('openid profile email'));
        $this->decide = new DecideConsent($held, $this->consents, $this->clock);

        $user = User::register(
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            'jane@example.com',
            null,
            $this->clock->now(),
        );
        $users->save($user);
        $this->jane = new EndUser($user->id);
        $clients->save(Client::register(
            ClientId::fromString('tpc_partner'),
            'Partner Analytics',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://partner.example/cb'), Url::fromString('https://partner.example/other')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->clock->now(),
        ));
        $this->api = ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://invoices.example/'),
            '',
            [Permission::of('invoices:read', 'Read your invoices'), Permission::of('invoices:write')],
            $this->clock->now(),
        );
        $this->resourceServers->save($this->api);
        $this->states->park(self::HANDLE, new PendingConsent(
            self::RESUME_AT,
            'https://partner.example/cb',
            'xyz',
            $user->id,
            ClientId::fromString('tpc_partner'),
            ScopeSet::fromString('openid email invoices:read invoices:write'),
            $this->api->id,
        ));
    }

    public function testTheScreenSaysWhoAsksOfWhomForWhatInTheServersOwnWords(): void
    {
        $screen = ($this->describe)(self::HANDLE, $this->jane);

        self::assertNotNull($screen);
        self::assertSame('Partner Analytics', $screen->clientName);
        self::assertSame('jane@example.com', $screen->email);
        self::assertEquals(
            [
                new ScopeLine('openid', 'Sign you in and know who you are'),
                new ScopeLine('email', 'See your email address'),
            ],
            $screen->oidcScopes,
        );
        self::assertNotNull($screen->api);
        // An API without a name is shown by its identifier, a permission without words by itself.
        self::assertSame('https://invoices.example/', $screen->api->name);
        self::assertEquals(
            [new ScopeLine('invoices:read', 'Read your invoices'), new ScopeLine('invoices:write', 'invoices:write')],
            $screen->api->permissions,
        );
        self::assertSame(['https://partner.example'], $screen->formOrigins);
        self::assertNotNull($this->states->find(self::HANDLE), 'Showing the screen decides nothing.');
    }

    public function testNobodyButThePersonAskedSeesTheScreen(): void
    {
        $stranger = new EndUser(UserId::fromString('00000000-0000-4000-8000-000000000002'));

        self::assertNull(($this->describe)(self::HANDLE, $stranger));
        self::assertNull(($this->decide)(self::HANDLE, $stranger, true));
        self::assertNull(($this->describe)('never-issued', $this->jane));
        self::assertNull(($this->describe)('', $this->jane));
        self::assertNotNull($this->states->find(self::HANDLE), "A stranger's answer spends nothing.");
    }

    public function testARequestForAnApiDeletedMeanwhileHasExpired(): void
    {
        $this->resourceServers->delete($this->api->id);

        self::assertNull(($this->describe)(self::HANDLE, $this->jane));
        self::assertNull(($this->decide)(self::HANDLE, $this->jane, true));
    }

    public function testAllowingRecordsTheConsentOnceAndResumesTheRequest(): void
    {
        $outcome = ($this->decide)(self::HANDLE, $this->jane, true);

        self::assertEquals(new ConsentGiven(self::RESUME_AT), $outcome);
        $consent = $this->consents->find($this->jane->userId, ClientId::fromString('tpc_partner'), $this->api->id);
        self::assertSame('openid email invoices:read invoices:write', $consent?->scope->toString());
        self::assertNull(($this->decide)(self::HANDLE, $this->jane, true), 'Decided once.');
    }

    public function testAllowingWidensWhatWasAgreedBefore(): void
    {
        $this->consents->save(UserConsent::give(
            $this->jane->userId,
            ClientId::fromString('tpc_partner'),
            $this->api->id,
            ScopeSet::fromString('profile'),
            new \DateTimeImmutable('2026-01-14T10:00:00Z'),
        ));

        ($this->decide)(self::HANDLE, $this->jane, true);

        $consent = $this->consents->find($this->jane->userId, ClientId::fromString('tpc_partner'), $this->api->id);
        self::assertNotNull($consent);
        self::assertTrue($consent->covers(ScopeSet::fromString('profile openid email invoices:read invoices:write')));
        self::assertEquals(new \DateTimeImmutable('2026-01-14T10:00:00Z'), $consent->grantedAt);
        self::assertEquals($this->clock->now(), $consent->updatedAt);
    }

    public function testRefusingSendsAccessDeniedToTheApplicationAndRecordsNothing(): void
    {
        $outcome = ($this->decide)(self::HANDLE, $this->jane, false);

        self::assertInstanceOf(RequestRefused::class, $outcome);
        self::assertSame('https://partner.example/cb', $outcome->redirectUri);
        self::assertSame(ErrorCode::AccessDenied, $outcome->error->error);
        self::assertSame('xyz', $outcome->state);
        self::assertSame([], $this->consents->ofUser($this->jane->userId));
        self::assertNull($this->states->find(self::HANDLE));
    }
}
