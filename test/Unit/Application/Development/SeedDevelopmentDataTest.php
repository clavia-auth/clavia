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
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
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

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->hasher = new FakePasswordHasher();
    }

    public function testItCreatesAUserWhoseStoredPasswordIsAHash(): void
    {
        $seeded = $this->seeder()('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');

        $user = $this->users->findByEmail('dev@clavia.test');
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
        $hash = $this->users->findByEmail('dev@clavia.test')?->passwordHash();

        $second = $this->seeder()('dev@clavia.test', 'another-password', 'http://localhost:9999/elsewhere');

        self::assertFalse($second->userCreated);
        self::assertFalse($second->clientCreated);
        self::assertTrue($second->clientId->equals($first->clientId));
        self::assertSame($hash, $this->users->findByEmail('dev@clavia.test')?->passwordHash());
        self::assertFalse($this->clients->find($first->clientId)?->hasRedirectUri('http://localhost:9999/elsewhere'));
    }

    public function testItRefusesOutsideADevelopmentDeployment(): void
    {
        try {
            $this->seeder(isDevelopment: false)('dev@clavia.test', 'devpassword', 'http://localhost:3000/callback');
            self::fail('Development data was seeded.');
        } catch (LogicException) {
            self::assertNull($this->users->findByEmail('dev@clavia.test'));
            self::assertNull($this->clients->findByName(SeedDevelopmentData::CLIENT_NAME));
        }
    }

    public function testARedirectUriThatIsNotAUrlIsRefusedBeforeAnythingIsCreated(): void
    {
        try {
            $this->seeder()('dev@clavia.test', 'devpassword', 'not a url');
            self::fail('The redirect URI was accepted.');
        } catch (InvalidValue) {
            self::assertNull($this->users->findByEmail('dev@clavia.test'));
        }
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
            new SecretGenerator($random),
            $random,
            new FrozenClock(),
            $isDevelopment,
        );
    }
}
