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
use Clavia\Adapter\Secondary\Redis\RedisMfaChallengeStore;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Contract\MfaChallengeStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisMfaChallengeStoreTest extends IntegrationTestCase
{
    use MfaChallengeStoreContract;

    #[\Override]
    protected function challenges(): MfaChallengeStore
    {
        return new RedisMfaChallengeStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testAChallengeLivesForItsLifetimeAndAFailureDoesNotExtendIt(): void
    {
        $this->challenges()->open('handle-1', $this->challenge(), 300);
        $key = Keys::forSecret('mfa-challenge', 'handle-1');
        self::assertGreaterThan(295, $this->redis()->ttl($key));

        $this->redis()->expire($key, 100);
        self::assertTrue($this->challenges()->recordFailure('handle-1', 5));

        self::assertLessThanOrEqual(100, $this->redis()->ttl($key));
        self::assertGreaterThan(0, $this->redis()->ttl($key));
    }

    public function testTheHandleNeverAppearsInAKey(): void
    {
        $this->challenges()->open('the-plain-handle', $this->challenge(), 300);

        $keys = $this->redis()->keys('*');

        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('the-plain-handle', implode('|', $keys));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $this->redis()->hMSet(Keys::forSecret('mfa-challenge', 'garbled'), [
            'user_id' => '0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d',
            'next_url' => '/',
            'amr' => '{',
        ]);
        $this->redis()->hMSet(Keys::forSecret('mfa-challenge', 'bad-user'), [
            'user_id' => 'x',
            'next_url' => '/',
            'amr' => '["pwd"]',
        ]);
        $this->redis()->hMSet(Keys::forSecret('mfa-challenge', 'bad-method'), [
            'user_id' => '0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d',
            'next_url' => '/',
            'amr' => '["nope"]',
        ]);
        $this->redis()->hMSet(Keys::forSecret('mfa-challenge', 'no-url'), [
            'user_id' => '0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d',
            'amr' => '["pwd"]',
        ]);

        self::assertNull($this->challenges()->find('garbled'));
        self::assertNull($this->challenges()->find('bad-user'));
        self::assertNull($this->challenges()->find('bad-method'));
        self::assertNull($this->challenges()->find('no-url'));
    }

    private function challenge(): MfaChallenge
    {
        return new MfaChallenge(
            UserId::fromString('0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d'),
            '/',
            null,
            [AuthenticationMethod::Password],
        );
    }
}
