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
use Clavia\Adapter\Secondary\Redis\RedisNonceRegistry;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;
use ClaviaTest\Support\Contract\NonceRegistryContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisNonceRegistryTest extends IntegrationTestCase
{
    use NonceRegistryContract;

    #[\Override]
    protected function nonces(): NonceRegistry
    {
        return new RedisNonceRegistry(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testAClaimExpiresOnItsOwn(): void
    {
        self::assertTrue($this->nonces()->claim(ClientId::fromString('spa'), Nonce::fromString('n-1'), 600));

        $ttl = $this->redis()->ttl(Keys::forSecret('nonce', 'spa:n-1'));

        self::assertGreaterThan(595, $ttl);
        self::assertLessThanOrEqual(600, $ttl);
    }

    public function testNeitherTheClientNorTheNonceAppearsInTheKey(): void
    {
        self::assertTrue($this->nonces()->claim(
            ClientId::fromString('the-client'),
            Nonce::fromString('the-nonce-value'),
            600,
        ));

        $keys = $this->redis()->keys('*');

        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('the-client', $keys[0]);
        self::assertStringNotContainsString('the-nonce-value', $keys[0]);
    }
}
