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
use Clavia\Adapter\Secondary\Redis\RedisAttemptCounter;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisSessionStore;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\SessionStore;
use ClaviaTest\Support\Contract\AttemptCounterContract;
use ClaviaTest\Support\Contract\SessionStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisAuthenticationStoresTest extends IntegrationTestCase
{
    use SessionStoreContract;
    use AttemptCounterContract;

    #[\Override]
    protected function sessions(): SessionStore
    {
        return new RedisSessionStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    #[\Override]
    protected function counter(): AttemptCounter
    {
        return new RedisAttemptCounter(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testASessionLivesForItsTimeToLiveAndExtendingRestartsIt(): void
    {
        $this->sessions()->save('session-1', $this->aSession(), 600);
        $key = Keys::forSecret('session', 'session-1');
        self::assertGreaterThan(595, $this->redis()->ttl($key));

        $this->redis()->expire($key, 10);
        $this->sessions()->extend('session-1', 600);

        self::assertGreaterThan(595, $this->redis()->ttl($key));
    }

    public function testNeitherTheSessionIdentifierNorACountedSubjectAppearsInAKey(): void
    {
        $this->sessions()->save('the-plain-session-id', $this->aSession(), 600);
        $this->counter()->increment('account:jane@example.com', 900);

        $keys = $this->redis()->keys('*');

        self::assertIsArray($keys);
        self::assertCount(2, $keys);
        self::assertStringNotContainsString('the-plain-session-id', implode('|', $keys));
        self::assertStringNotContainsString('jane', implode('|', $keys));
    }

    public function testAFailureWindowIsTheGivenOneAndRestartsWithEachFailure(): void
    {
        $this->counter()->increment('a', 900);
        $key = Keys::forSecret('login-attempts', 'a');
        $this->redis()->expire($key, 10);

        $this->counter()->increment('a', 900);

        self::assertGreaterThan(895, $this->redis()->ttl($key));
        self::assertSame(2, $this->counter()->count('a'));
    }

    public function testASessionEntryThatCannotBeReadIsNoSession(): void
    {
        $valid = [
            'user_id' => '3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6f',
            'authenticated_at' => '2026-01-15T10:00:00.000000+00:00',
            'expires_at' => '2026-01-22T10:00:00.000000+00:00',
            'amr' => ['pwd'],
            'sid' => 'the-sid',
        ];
        $variants = [
            'valid' => $valid,
            'not-json' => '{',
            'not-an-object' => '"x"',
            'unknown-method' => ['amr' => ['telepathy']] + $valid,
            'no-method' => ['amr' => []] + $valid,
            'bad-user' => ['user_id' => 'nope'] + $valid,
            'bad-instant' => ['authenticated_at' => 'yesterday'] + $valid,
            'ends-before-it-begins' => ['expires_at' => '2026-01-14T10:00:00.000000+00:00'] + $valid,
            'no-sid' => ['sid' => ''] + $valid,
            'amr-not-a-list' => ['amr' => ['a' => 'pwd']] + $valid,
        ];
        foreach ($variants as $name => $value) {
            $this->redis()->set(
                Keys::forSecret('session', $name),
                is_string($value) ? $value : json_encode($value, JSON_THROW_ON_ERROR),
            );
        }

        self::assertNotNull($this->sessions()->find('valid'));
        foreach (array_keys($variants) as $name) {
            if ($name !== 'valid') {
                self::assertNull($this->sessions()->find($name), $name);
            }
        }
    }
}
