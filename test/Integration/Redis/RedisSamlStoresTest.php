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
use Clavia\Adapter\Secondary\Redis\RedisSamlAssertionReplayCache;
use Clavia\Adapter\Secondary\Redis\RedisSamlResponseStore;
use Clavia\Application\Port\Saml\ParkedSamlResponse;
use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Connection\ConnectionName;
use ClaviaTest\Support\Contract\SamlStoresContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisSamlStoresTest extends IntegrationTestCase
{
    use SamlStoresContract;

    #[\Override]
    protected function samlResponses(): SamlResponseStore
    {
        return new RedisSamlResponseStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    #[\Override]
    protected function samlAssertions(): SamlAssertionReplayCache
    {
        return new RedisSamlAssertionReplayCache(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testAParkedResponseLivesAMinuteUnderTheDigestOfItsHandle(): void
    {
        $this->samlResponses()->park('handle-1', new ParkedSamlResponse(ConnectionName::fromString('acme'), 'x', 'y'));

        $keys = $this->redis()->keys('saml-response:*');
        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('handle-1', $keys[0]);
        self::assertLessThanOrEqual(SamlResponseStore::TTL_SECONDS, $this->redis()->ttl($keys[0]));
    }
}
