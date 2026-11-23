<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Redis;

use Clavia\Adapter\Secondary\Redis\Keys;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisPushedAuthorizationRequestStore;
use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use ClaviaTest\Support\Contract\PushedAuthorizationRequestStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisPushedAuthorizationRequestStoreTest extends IntegrationTestCase
{
    use PushedAuthorizationRequestStoreContract;

    #[\Override]
    protected function pushedRequests(): PushedAuthorizationRequestStore
    {
        return new RedisPushedAuthorizationRequestStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testItIsKeptForItsLifetimeUnderTheDigestOfItsHandle(): void
    {
        $this->pushedRequests()->push('handle-1', new PushedAuthorizationRequest(ClientId::fromString('spa'), []), 60);

        $ttl = $this->redis()->ttl(Keys::forSecret('pushed-request', 'handle-1'));

        self::assertGreaterThan(55, $ttl);
        self::assertLessThanOrEqual(60, $ttl);
        self::assertSame([], $this->redis()->keys('*handle-1*'));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $this->redis()->set(Keys::forSecret('pushed-request', 'handle-1'), '{"client_id":"spa","parameters":[[1]]}');

        self::assertNull($this->pushedRequests()->find('handle-1'));
    }
}
