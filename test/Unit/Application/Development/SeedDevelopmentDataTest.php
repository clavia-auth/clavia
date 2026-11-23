<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Development;

use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use LogicException;
use PHPUnit\Framework\TestCase;

final class SeedDevelopmentDataTest extends TestCase
{
    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private FakePasswordHasher $hasher;
    private InMemorySigningKeys $signingKeys;

    #[\Override]
    protected function setUp(): void
    {
        $this->signingKeys = new InMemorySigningKeys(new FrozenClock());
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->hasher = new FakePasswordHasher();
    }

    public function testItCreatesAUserWhoseStoredPasswordIsAHash(): void
    {
        $seeded = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        $user = $this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test');
        self::assertTrue($seeded->userCreated);
        self::assertSame('dev@clavia.test', $seeded->userEmail);
        self::assertNotNull($user);
        self::assertTrue($user->isActive());
        self::assertNotSame('devpassword', $user->passwordHash());
        self::assertTrue($this->hasher->verify('devpassword', (string) $user->passwordHash()));
    }

    public function testItRegistersAPublicPkceClientForTheRedirectUri(): void
    {
        $seeded = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        $client = $this->clients->find($seeded->clientId);
        self::assertTrue($seeded->clientCreated);
        self::assertNotNull($client);
        self::assertSame(SeedDevelopmentData::CLIENT_NAME, $client->name);
        self::assertTrue($client->isPublic());
        self::assertSame(ClientAuthMethod::None, $client->authMethod);
        self::assertNull($client->secretHash());
        self::assertTrue($client->hasRedirectUri('http://localhost:3000/callback'));
        self::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        self::assertSame([ResponseType::Code], $client->responseTypes);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{32}$/D', $client->id->value);
    }

    public function testRunningItAgainCreatesNothingAndChangesNothing(): void
    {
        $first = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');
        $hash = $this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test')?->passwordHash();

        $second = $this->seeder()('dev@clavia.test', 'another-password', 'http://localhost:9999/elsewhere');

        self::assertFalse($second->userCreated);
        self::assertFalse($second->clientCreated);
        self::assertTrue($second->clientId->equals($first->clientId));
        $again = $this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test');
        self::assertSame($hash, $again?->passwordHash());
        self::assertFalse($this->clients->find($first->clientId)?->hasRedirectUri('http://localhost:9999/elsewhere'));
    }

    public function testARerunHashesThePasswordAgainWhenTheStoredHashIsOutdated(): void
    {
        // A database seeded before the hash changed (bcrypt, then PBKDF2): the user would be locked out.
        $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');
        $before = $this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test')?->passwordHash();
        $this->hasher->outdated = true;

        $second = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        self::assertFalse($second->userCreated);
        $after = $this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test')?->passwordHash();
        self::assertNotSame($before, $after, 'Hashed again.');
        self::assertTrue($this->hasher->verify('devpassword', (string) $after));
    }

    public function testItRefusesOutsideADevelopmentDeployment(): void
    {
        try {
            $this->seeder(isDevelopment: false)('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');
            self::fail('Development data was seeded.');
        } catch (LogicException) {
            self::assertNull($this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test'));
            self::assertNull($this->clients->findByName(SeedDevelopmentData::CLIENT_NAME));
        }
    }

    public function testARedirectUriThatIsNotAUrlIsRefusedBeforeAnythingIsCreated(): void
    {
        try {
            $this->seeder()('dev@clavia.test', 'devpassword', 'not a url');
            self::fail('The redirect URI was accepted.');
        } catch (InvalidValue) {
            self::assertNull($this->users->findByEmail(ConnectionName::defaultPool(), 'dev@clavia.test'));
        }
    }

    public function testItCreatesASigningKeyWhenNoneIsActive(): void
    {
        $seeded = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        self::assertTrue($seeded->signingKeyCreated);
        self::assertSame($seeded->signingKeyId, $this->signingKeys->activeKey()->kid);
    }

    public function testARerunKeepsTheActiveSigningKey(): void
    {
        $first = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');
        $second = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        self::assertFalse($second->signingKeyCreated);
        self::assertSame($first->signingKeyId, $second->signingKeyId);
        self::assertCount(1, $this->signingKeys->all());
    }

    public function testAnEmailThatIsNotAnAddressIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->seeder()('not-an-address', 'devpassword', 'http://localhost:3000/callback');
    }

    private function seeder(bool $isDevelopment = true): SeedDevelopmentData
    {
        $random = new SeededRandomSource(1);

        return new SeedDevelopmentData(
            $this->users,
            $this->clients,
            $this->hasher,
            new InMemoryTransactionManager(),
            $this->signingKeys,
            SigningAlgorithm::RS256,
            new SecretGenerator($random),
            $random,
            new FrozenClock(),
            $isDevelopment,
        );
    }
}
