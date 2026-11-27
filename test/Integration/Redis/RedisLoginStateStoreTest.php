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
use Clavia\Adapter\Secondary\Redis\RedisLoginStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use ClaviaTest\Support\Contract\LoginStateStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisLoginStateStoreTest extends IntegrationTestCase
{
    use LoginStateStoreContract;

    #[\Override]
    protected function loginStates(): LoginStateStore
    {
        return new RedisLoginStateStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testAnEntryExpiresOnItsOwnAndReadingDoesNotExtendIt(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a'));
        $key = Keys::forSecret('login-state', 'handle-1');
        $this->redis()->expire($key, 100);

        $this->loginStates()->get('handle-1');

        self::assertLessThanOrEqual(100, $this->redis()->ttl($key));
    }

    public function testItIsStoredForItsLifetime(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a'));

        $ttl = $this->redis()->ttl(Keys::forSecret('login-state', 'handle-1'));

        self::assertGreaterThan(LoginState::LIFETIME_SECONDS - 5, $ttl);
        self::assertLessThanOrEqual(LoginState::LIFETIME_SECONDS, $ttl);
    }

    public function testTheApplicationIsKeptADayUnderItsOwnKey(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a', ClientId::fromString('spa')));

        $key = Keys::forSecret('login-state-application', 'handle-1');
        self::assertSame('spa', $this->redis()->get($key), 'The client id, and nothing else.');
        self::assertGreaterThan(LoginState::APPLICATION_REMEMBERED_SECONDS - 5, $this->redis()->ttl($key));
        self::assertLessThanOrEqual(LoginState::APPLICATION_REMEMBERED_SECONDS, $this->redis()->ttl($key));
    }

    public function testTheHandleNeverAppearsInAKey(): void
    {
        $this->loginStates()->put('the-plain-handle', new LoginState('/a', ClientId::fromString('spa')));

        $keys = $this->redis()->keys('*');

        self::assertIsArray($keys);
        self::assertCount(2, $keys);
        self::assertStringNotContainsString('the-plain-handle', implode('|', $keys));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $this->redis()->set(Keys::forSecret('login-state', 'garbled'), '{not json');
        $this->redis()->set(Keys::forSecret('login-state', 'wrong-shape'), '{"next_url":42}');
        $this->redis()->set(Keys::forSecret('login-state', 'bad-client'), '{"next_url":"/a","client_id":"has space"}');

        self::assertNull($this->loginStates()->get('garbled'));
        self::assertNull($this->loginStates()->get('wrong-shape'));
        self::assertNull($this->loginStates()->get('bad-client'));
    }
}
