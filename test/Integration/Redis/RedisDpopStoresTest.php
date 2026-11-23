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
use Clavia\Adapter\Secondary\Redis\RedisDpopNonces;
use Clavia\Adapter\Secondary\Redis\RedisDpopReplayCache;
use Clavia\Application\Port\DpopNonces;
use Clavia\Application\Port\DpopReplayCache;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Contract\DpopNoncesContract;
use ClaviaTest\Support\Contract\DpopReplayCacheContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisDpopStoresTest extends IntegrationTestCase
{
    use DpopReplayCacheContract;
    use DpopNoncesContract;

    #[\Override]
    protected function replays(): DpopReplayCache
    {
        return new RedisDpopReplayCache(new RedisConnection(TestEnvironment::redisUrl()));
    }

    #[\Override]
    protected function nonces(FrozenClock $clock): DpopNonces
    {
        return new RedisDpopNonces(
            new RedisConnection(TestEnvironment::redisUrl()),
            new SecretGenerator(new SeededRandomSource(random_int(1, PHP_INT_MAX))),
            $clock,
            300,
        );
    }

    public function testAProofIsRememberedForItsLifetimeOnly(): void
    {
        $this->replays()->claim(JwkThumbprint::fromString('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'), 'jti-1', 65);

        $keys = $this->redis()->keys('dpop-jti:*');
        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertGreaterThan(60, $this->redis()->ttl($keys[0]));
        self::assertStringNotContainsString('jti-1', $keys[0]);
    }
}
