<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Redis;

use Clavia\Infrastructure\Redis\Keys;
use Clavia\Infrastructure\Redis\RedisConnection;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;

final class RedisConnectionTest extends IntegrationTestCase
{
    public function testItConnectsToTheDatabaseTheUrlNames(): void
    {
        $client = new RedisConnection(TestEnvironment::redisUrl())->client();
        $client->set('probe', 'in-database-1');

        // The same server, database 0: the key is not there.
        $urlOfDatabaseZero = (string) preg_replace('#/\d+$#', '/0', TestEnvironment::redisUrl());
        $databaseZero = new RedisConnection($urlOfDatabaseZero)->client();

        self::assertSame('in-database-1', $client->get('probe'));
        self::assertFalse($databaseZero->get('probe'));
    }

    public function testTheClientIsOpenedOnceAndReused(): void
    {
        $connection = new RedisConnection(TestEnvironment::redisUrl());

        self::assertSame($connection->client(), $connection->client());
    }

    public function testBuildingItOpensNoConnection(): void
    {
        $unreachable = new RedisConnection('redis://127.0.0.1:1/1');

        $this->expectException(\RedisException::class);

        $unreachable->client();
    }

    public function testWhatIsStoredExpiresOnItsOwn(): void
    {
        $this->redis()->setex(Keys::forSecret('session', 'cookie-value'), 60, 'payload');

        $ttl = $this->redis()->ttl(Keys::forSecret('session', 'cookie-value'));

        self::assertGreaterThan(0, $ttl);
        self::assertLessThanOrEqual(60, $ttl);
    }

    public function testEachTestStartsWithAnEmptyDatabase(): void
    {
        self::assertSame(0, $this->redis()->dbSize());
    }

    public function testASecretNeverAppearsInAKey(): void
    {
        $key = Keys::forSecret('session', 'the-cookie-value');

        self::assertMatchesRegularExpression('/^session:[0-9a-f]{64}$/D', $key);
        self::assertStringNotContainsString('the-cookie-value', $key);
        self::assertSame($key, Keys::forSecret('session', 'the-cookie-value'));
        self::assertNotSame($key, Keys::forSecret('login-state', 'the-cookie-value'));
    }

    public function testAnIdentifierThatIsNotASecretIsKeptReadable(): void
    {
        self::assertSame('user-sessions:42', Keys::forIdentifier('user-sessions', '42'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function urlsThatAreNotRedis(): iterable
    {
        yield 'another scheme' => ['http://localhost:6379/1'];
        yield 'no host' => ['redis:///1'];
        yield 'a database name' => ['redis://localhost:6379/sessions'];
        yield 'not a URL' => ['localhost'];
    }

    #[DataProvider('urlsThatAreNotRedis')]
    public function testAMalformedUrlIsRefused(string $url): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RedisConnection($url)->client();
    }
}
