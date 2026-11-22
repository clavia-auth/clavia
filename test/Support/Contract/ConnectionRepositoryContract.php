<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\OidcSettings;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ConnectionRepository} does: it starts with the built-in connections,
 * keeps an operator's pools and providers whole, and a deleted connection stops being
 * enabled for any application.
 */
trait ConnectionRepositoryContract
{
    abstract protected function connections(): ConnectionRepository;

    abstract protected function clients(): ClientRepository;

    #[Test]
    public function theBuiltInConnectionsAreThereFromTheStart(): void
    {
        $all = $this->connections()->all();

        self::assertSame(
            ['email', 'github', 'google', 'password'],
            array_map(static fn (Connection $connection): string => $connection->name->value, $all),
        );
        $pool = $this->connections()->find(ConnectionName::defaultPool());
        self::assertNotNull($pool);
        self::assertSame(ConnectionStrategy::Database, $pool->strategy);
        self::assertTrue($pool->isEnabled);
        self::assertTrue($pool->isDomainConnection);
        self::assertTrue($pool->isBuiltIn());
        self::assertSame(ConnectionStrategy::Social, $this->connections()->find(self::named('google'))?->strategy);
        self::assertFalse($this->connections()->find(self::named('github'))?->isDomainConnection);
        self::assertNull($this->connections()->find(self::named('gitlab')));
        $email = $this->connections()->find(ConnectionName::email());
        self::assertNotNull($email);
        self::assertSame(ConnectionStrategy::Passwordless, $email->strategy);
        self::assertTrue($email->isEnabled);
        self::assertFalse($email->isDomainConnection, 'Strangers are not handed accounts made from an address.');
        self::assertTrue($email->isBuiltIn());
    }

    #[Test]
    public function anOidcConnectionIsReadBackWhole(): void
    {
        $this->connections()->add($this->acme());

        $read = $this->connections()->find(self::named('acme'));

        self::assertNotNull($read);
        self::assertSame('Acme SSO', $read->displayName);
        self::assertSame(ConnectionStrategy::Oidc, $read->strategy);
        self::assertTrue($read->isEnabled);
        self::assertFalse($read->isDomainConnection);
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $read->createdAt);
        $oidc = $read->oidc;
        self::assertNotNull($oidc);
        self::assertSame('https://idp.example', $oidc->issuer->value);
        self::assertSame('clavia', $oidc->clientId);
        self::assertSame('sealed-secret', $oidc->encryptedClientSecret);
        self::assertSame('openid email profile', $oidc->scope->toString());
        self::assertSame('https://idp.example/authorize', $oidc->authorizationEndpoint->value);
        self::assertSame('https://idp.example/token', $oidc->tokenEndpoint->value);
        self::assertSame('https://idp.example/jwks', $oidc->jwksUri->value);
    }

    #[Test]
    public function aNameIsTakenOnce(): void
    {
        $this->connections()->add($this->acme());

        $this->expectException(AlreadyExists::class);

        $this->connections()->add($this->acme());
    }

    #[Test]
    public function aBuiltInNameIsAlreadyTaken(): void
    {
        $this->expectException(AlreadyExists::class);

        $this->connections()->add(Connection::pool(
            ConnectionName::defaultPool(),
            'Another',
            true,
            false,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }

    #[Test]
    public function aPoolKeepsItsSelfServiceSettings(): void
    {
        $this->connections()->add(Connection::pool(
            ConnectionName::fromString('customers'),
            'Customers',
            true,
            false,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            true,
            true,
        ));
        $created = $this->connections()->find(ConnectionName::fromString('customers'));
        self::assertNotNull($created);
        self::assertTrue($created->allowsSignUp);
        self::assertTrue($created->requiresVerifiedEmail);

        $this->connections()->save($created->switched(null, null, null, false, false));

        $saved = $this->connections()->find(ConnectionName::fromString('customers'));
        self::assertNotNull($saved);
        self::assertFalse($saved->allowsSignUp);
        self::assertFalse($saved->requiresVerifiedEmail);
    }

    #[Test]
    public function savingStoresTheSwitchesTheLabelAndTheProviderSettings(): void
    {
        $this->connections()->add($this->acme());
        $changed = $this->acme()
            ->switched(false, true, 'Acme')
            ->withOidc($this->settings('https://idp.example/v2/keys'));

        $this->connections()->save($changed);

        $read = $this->connections()->find(self::named('acme'));
        self::assertNotNull($read);
        self::assertFalse($read->isEnabled);
        self::assertTrue($read->isDomainConnection);
        self::assertSame('Acme', $read->displayName);
        self::assertSame('https://idp.example/v2/keys', $read->oidc?->jwksUri->value);
    }

    #[Test]
    public function aDeletedConnectionIsGoneAndNoLongerEnabledForAnyApplication(): void
    {
        $this->connections()->add($this->acme());
        $client = $this->aClientEnabling([ConnectionName::defaultPool(), self::named('acme')]);
        $this->clients()->save($client);

        $this->connections()->delete(self::named('acme'));

        self::assertNull($this->connections()->find(self::named('acme')));
        self::assertSame(
            ['password'],
            array_map(
                static fn (ConnectionName $name): string => $name->value,
                $this->clients()->find($client->id)?->connections ?? [],
            ),
        );
    }

    private function acme(): Connection
    {
        return Connection::openIdProvider(
            self::named('acme'),
            'Acme SSO',
            $this->settings('https://idp.example/jwks'),
            true,
            false,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }

    private function settings(string $jwksUri): OidcSettings
    {
        return OidcSettings::of(
            'https://idp.example',
            'clavia',
            'sealed-secret',
            ScopeSet::fromString('openid email profile'),
            'https://idp.example/authorize',
            'https://idp.example/token',
            $jwksUri,
        );
    }

    /**
     * @param list<ConnectionName> $connections
     */
    private function aClientEnabling(array $connections): Client
    {
        return Client::register(
            ClientId::fromString('spa-with-connections'),
            'SPA',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://app.example/callback')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            [],
            $connections,
        );
    }

    private static function named(string $name): ConnectionName
    {
        return ConnectionName::fromString($name);
    }
}
