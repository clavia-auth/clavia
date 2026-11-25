<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Claims\ClaimDestination;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ClientRepository} must do.
 */
trait ClientRepositoryContract
{
    abstract protected function clients(): ClientRepository;

    #[Test]
    public function anApplicationsCustomClaimsAreSavedAndReadBackWhole(): void
    {
        $claims = ClaimMappings::of([
            ClaimMapping::forApplication(
                ClaimName::fromString('tenant', onAnApi: false),
                ClaimSource::fromString('app_metadata.tenant'),
                [ClaimDestination::UserInfo, ClaimDestination::IdToken],
            ),
            ClaimMapping::forApplication(
                ClaimName::fromString('https://example.com/deployment', onAnApi: false),
                ClaimSource::fromString('constant', '{"region":"eu","n":1}'),
                [ClaimDestination::IdToken],
            ),
        ]);
        $this->clients()->save($this->aPublicClient('spa', 'My SPA')->withClaims($claims));

        self::assertSame($claims->toJson(), $this->clients()->find(ClientId::fromString('spa'))?->claims->toJson());
    }

    #[Test]
    public function aSavedPublicClientIsReadBackWhole(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));

        $client = $this->clients()->find(ClientId::fromString('spa'));

        self::assertNotNull($client);
        self::assertSame('spa', $client->id->value);
        self::assertSame('My SPA', $client->name);
        self::assertSame(ClientType::Public, $client->type);
        self::assertSame(ClientAuthMethod::None, $client->authMethod);
        self::assertNull($client->secretHash());
        self::assertSame(
            ['https://app.example/cb?x=1&y=%C3%A9', 'http://localhost:3000/callback'],
            array_map(static fn (Url $uri): string => $uri->value, $client->redirectUris),
        );
        self::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        self::assertSame([ResponseType::Code], $client->responseTypes);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $client->createdAt);
        self::assertSame([], $client->postLogoutRedirectUris);
        self::assertNull($client->backChannelLogout);
    }

    #[Test]
    public function aBackChannelLogoutRegistrationIsKeptAndCleared(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA')->withBackChannelLogout(
            new BackChannelLogout(Url::fromString('https://app.example/logout?x=1'), true),
        ));

        $read = $this->clients()->find(ClientId::fromString('spa'));
        self::assertNotNull($read);
        self::assertSame('https://app.example/logout?x=1', $read->backChannelLogout?->uri->value);
        self::assertTrue($read->backChannelLogout?->sessionRequired);

        $this->clients()->save($read->withBackChannelLogout(null));
        self::assertNull($this->clients()->find(ClientId::fromString('spa'))?->backChannelLogout);
    }

    #[Test]
    public function postLogoutRedirectUrisAreKeptAsRegistered(): void
    {
        $client = $this->aPublicClient('spa', 'My SPA')->reconfigure(
            'My SPA',
            [Url::fromString('https://app.example/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            ClientAuthMethod::None,
            [Url::fromString('https://app.example/bye?lang=fr'), Url::fromString('https://app.example/out')],
        );
        $this->clients()->save($client);

        $read = $this->clients()->find(ClientId::fromString('spa'));

        self::assertNotNull($read);
        self::assertSame(
            ['https://app.example/bye?lang=fr', 'https://app.example/out'],
            array_map(static fn (Url $uri): string => $uri->value, $read->postLogoutRedirectUris),
        );
        self::assertTrue($read->hasPostLogoutRedirectUri('https://app.example/out'));
        self::assertFalse($read->hasPostLogoutRedirectUri('https://app.example/out/'));
        self::assertFalse($read->hasPostLogoutRedirectUri('https://app.example/cb'));
    }

    #[Test]
    public function aConfidentialClientKeepsItsSecretHashAndMethod(): void
    {
        $this->clients()->save($this->aConfidentialClient('backend'));

        $client = $this->clients()->find(ClientId::fromString('backend'));

        self::assertNotNull($client);
        self::assertSame(ClientType::Confidential, $client->type);
        self::assertSame(ClientAuthMethod::ClientSecretBasic, $client->authMethod);
        self::assertSame('$2y$04$hash', $client->secretHash());
        self::assertTrue($client->requiresPkce);
    }

    #[Test]
    public function aConfidentialClientRelievedOfPkceStaysRelieved(): void
    {
        $this->clients()->save($this->aConfidentialClient('backend')->withPkceRequired(false));

        self::assertFalse($this->clients()->find(ClientId::fromString('backend'))?->requiresPkce);
    }

    #[Test]
    public function anUnknownClientIsNull(): void
    {
        self::assertNull($this->clients()->find(ClientId::fromString('nope')));
        self::assertNull($this->clients()->findByName('Nope'));
    }

    #[Test]
    public function theClientIdIsMatchedExactly(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));

        self::assertNull($this->clients()->find(ClientId::fromString('SPA')));
        self::assertNull($this->clients()->find(ClientId::fromString('sp%')));
    }

    #[Test]
    public function aClientIsFoundByNameOldestFirst(): void
    {
        $this->clients()->save($this->aPublicClient('newer', 'Shared name', '2026-03-01T00:00:00Z'));
        $this->clients()->save($this->aPublicClient('older', 'Shared name', '2026-01-01T00:00:00Z'));

        self::assertSame('older', $this->clients()->findByName('Shared name')?->id->value);
    }

    #[Test]
    public function savingAgainReplacesTheRegistration(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));

        $this->clients()->save(Client::register(
            ClientId::fromString('spa'),
            'Renamed',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://app.example/new')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        $client = $this->clients()->find(ClientId::fromString('spa'));
        self::assertNotNull($client);
        self::assertSame('Renamed', $client->name);
        self::assertTrue($client->hasRedirectUri('https://app.example/new'));
        self::assertFalse($client->hasRedirectUri('http://localhost:3000/callback'));
    }

    #[Test]
    public function aRedirectOriginIsRegisteredWhenAnyClientPointsAtIt(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));
        $this->clients()->save($this->aConfidentialClient('backend'));

        self::assertTrue($this->clients()->registersRedirectOrigin('https://app.example'));
        self::assertTrue($this->clients()->registersRedirectOrigin('http://localhost:3000'));
        self::assertTrue($this->clients()->registersRedirectOrigin('https://backend.example'));
    }

    #[Test]
    public function anOriginIsMatchedWholeAndExactly(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));

        self::assertFalse($this->clients()->registersRedirectOrigin('http://app.example'));
        self::assertFalse($this->clients()->registersRedirectOrigin('https://app.example:8443'));
        self::assertFalse($this->clients()->registersRedirectOrigin('https://evil.app.example'));
        self::assertFalse($this->clients()->registersRedirectOrigin('https://app.example/cb'));
        self::assertFalse($this->clients()->registersRedirectOrigin('http://localhost'));
        self::assertFalse($this->clients()->registersRedirectOrigin(''));
    }

    #[Test]
    public function withoutClientsNoOriginIsRegistered(): void
    {
        self::assertFalse($this->clients()->registersRedirectOrigin('https://app.example'));
    }

    #[Test]
    public function clientsArePagedNewestFirstAndSearchedByIdAndName(): void
    {
        $this->clients()->save($this->aPublicClient('alpha-app', 'Billing', '2026-01-15T10:00:00Z'));
        $this->clients()->save($this->aPublicClient('beta-app', 'Reports', '2026-01-15T11:00:00Z'));
        $this->clients()->save($this->aPublicClient('gamma-app', 'Billing 100%', '2026-01-15T12:00:00Z'));

        $first = $this->clients()->page(PageRequest::of(1, 2));
        self::assertSame(3, $first->total);
        self::assertSame(
            ['gamma-app', 'beta-app'],
            array_map(static fn (Client $c): string => $c->id->value, $first->items),
        );
        self::assertSame(['alpha-app'], array_map(
            static fn (Client $c): string => $c->id->value,
            $this->clients()->page(PageRequest::of(2, 2))->items,
        ));

        self::assertSame(2, $this->clients()->page(PageRequest::of(search: 'BILLING'))->total);
        self::assertSame(1, $this->clients()->page(PageRequest::of(search: 'beta-'))->total);
        // `%` and `_` are characters, not wildcards.
        self::assertSame(1, $this->clients()->page(PageRequest::of(search: '100%'))->total);
        self::assertSame(0, $this->clients()->page(PageRequest::of(search: 'a_p'))->total);
    }

    #[Test]
    public function aDeletedClientIsGone(): void
    {
        $this->clients()->save($this->aPublicClient('doomed', 'Doomed'));
        $this->clients()->save($this->aPublicClient('kept', 'Kept'));

        $this->clients()->delete(ClientId::fromString('doomed'));
        $this->clients()->delete(ClientId::fromString('never-existed'));

        self::assertNull($this->clients()->find(ClientId::fromString('doomed')));
        self::assertNotNull($this->clients()->find(ClientId::fromString('kept')));
    }

    #[Test]
    public function theConnectionsAClientEnablesAreStoredAndReplacedWhole(): void
    {
        $client = $this->aPublicClient('spa', 'SPA')->withConnections(
            [ConnectionName::fromString('google'), ConnectionName::defaultPool()],
        );
        $this->clients()->save($client);

        self::assertSame(['google', 'password'], $this->enabledFor('spa'));

        $this->clients()->save($client->withConnections([ConnectionName::fromString('github')]));
        self::assertSame(['github'], $this->enabledFor('spa'));

        $this->clients()->save($client->withConnections([]));
        self::assertSame([], $this->enabledFor('spa'));
    }

    /** @return list<string> */
    private function enabledFor(string $id): array
    {
        return array_map(
            static fn (ConnectionName $name): string => $name->value,
            $this->clients()->find(ClientId::fromString($id))?->connections ?? [],
        );
    }

    private function aPublicClient(string $id, string $name, string $createdAt = '2026-01-15T10:00:00Z'): Client
    {
        return Client::register(
            ClientId::fromString($id),
            $name,
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://app.example/cb?x=1&y=%C3%A9'), Url::fromString('http://localhost:3000/callback')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable($createdAt),
        );
    }

    private function aConfidentialClient(string $id): Client
    {
        return Client::register(
            ClientId::fromString($id),
            'Backend',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            '$2y$04$hash',
            [Url::fromString('https://backend.example/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
