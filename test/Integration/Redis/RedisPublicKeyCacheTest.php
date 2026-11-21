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
use Clavia\Adapter\Secondary\Redis\RedisPublicKeyCache;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestSigningKeys;

final class RedisPublicKeyCacheTest extends IntegrationTestCase
{
    private const string ARN = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

    public function testAPublicKeyIsReadBackByItsReferenceForADay(): void
    {
        $cache = $this->cache();
        self::assertNull($cache->get(self::ARN, SigningAlgorithm::RS256));

        $cache->put(self::ARN, TestSigningKeys::publicJwk());

        self::assertEquals(TestSigningKeys::publicJwk(), $cache->get(self::ARN, SigningAlgorithm::RS256));
        self::assertNull($cache->get('1234abcd-12ab-34cd-56ef-1234567890ab', SigningAlgorithm::RS256));
        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringStartsWith('signing-public-key:', $keys[0]);
        self::assertStringNotContainsString('111122223333', $keys[0], 'The reference names the account.');
        self::assertGreaterThan(RedisPublicKeyCache::TTL - 5, $this->redis()->ttl($keys[0]));
    }

    public function testAnEntryThatIsNotAValidPublicKeyIsAMiss(): void
    {
        $cache = $this->cache();
        $cache->put(self::ARN, TestSigningKeys::publicJwk());
        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        $key = $keys[0] ?? null;
        self::assertIsString($key);

        $forged = '{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"forged","alg":"RS256","use":"sig"}';
        foreach (['not json', '[]', $forged] as $entry) {
            $this->redis()->set($key, $entry);
            self::assertNull($cache->get(self::ARN, SigningAlgorithm::RS256), $entry);
        }
    }

    private function cache(): RedisPublicKeyCache
    {
        return new RedisPublicKeyCache(new RedisConnection(TestEnvironment::redisUrl()));
    }
}
