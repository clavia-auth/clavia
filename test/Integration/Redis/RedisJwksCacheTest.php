<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Redis;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisJwksCache;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisJwksCacheTest extends IntegrationTestCase
{
    private const string JWKS_URI = 'https://idp.example/jwks';

    public function testAKeySetIsReadBackByItsUriUntilItExpires(): void
    {
        $cache = $this->cache();
        self::assertNull($cache->get(self::JWKS_URI));

        $cache->put(self::JWKS_URI, '{"keys":[]}', 3600);

        self::assertSame('{"keys":[]}', $cache->get(self::JWKS_URI));
        self::assertNull($cache->get('https://idp.example/other-keys'));
        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('idp.example', $keys[0]);
        $ttl = $this->redis()->ttl($keys[0]);
        self::assertGreaterThan(3595, $ttl);
        self::assertLessThanOrEqual(3600, $ttl);
    }

    public function testPuttingAgainReplacesTheSet(): void
    {
        $cache = $this->cache();

        $cache->put(self::JWKS_URI, '{"keys":[1]}', 3600);
        $cache->put(self::JWKS_URI, '{"keys":[2]}', 3600);

        self::assertSame('{"keys":[2]}', $cache->get(self::JWKS_URI));
    }

    private function cache(): RedisJwksCache
    {
        return new RedisJwksCache(new RedisConnection(TestEnvironment::redisUrl()));
    }
}
