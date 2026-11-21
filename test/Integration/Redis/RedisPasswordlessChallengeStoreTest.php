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
use Clavia\Adapter\Secondary\Redis\RedisPasswordlessChallengeStore;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use ClaviaTest\Support\Contract\PasswordlessChallengeStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisPasswordlessChallengeStoreTest extends IntegrationTestCase
{
    use PasswordlessChallengeStoreContract;

    #[\Override]
    protected function challenges(): PasswordlessChallengeStore
    {
        return new RedisPasswordlessChallengeStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testAChallengeLivesForItsLifetimeAndAFailureDoesNotExtendIt(): void
    {
        $this->challenges()->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 900);
        $key = Keys::forSecret('passwordless', 'link-1');
        self::assertGreaterThan(895, $this->redis()->ttl($key));

        $this->redis()->expire($key, 100);
        self::assertTrue($this->challenges()->recordFailure('link-1', 5));

        self::assertLessThanOrEqual(100, $this->redis()->ttl($key));
        self::assertGreaterThan(0, $this->redis()->ttl($key));
    }

    public function testNeitherTheHandleNorTheCodeIsStored(): void
    {
        $this->challenges()->open('the-plain-handle', PasswordlessChallenge::forCode(
            'jane@example.com',
            'the-plain-handle',
            OneTimeCode::fromTyped('424242'),
            '/',
            null,
            null,
        ), 300);

        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('the-plain-handle', implode('|', $keys));
        $fields = $this->redis()->hGetAll(Keys::forSecret('passwordless', 'the-plain-handle'));
        self::assertIsArray($fields);
        self::assertStringNotContainsString('424242', implode('|', $fields));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $valid = ['email' => 'jane@example.com', 'mode' => 'link', 'code_digest' => '', 'next_url' => '/'];
        $this->redis()->hMSet(Keys::forSecret('passwordless', 'bad-mode'), ['mode' => 'sms'] + $valid);
        $this->redis()->hMSet(Keys::forSecret('passwordless', 'no-email'), ['email' => ''] + $valid);
        $this->redis()->hMSet(Keys::forSecret('passwordless', 'code-without-digest'), ['mode' => 'code'] + $valid);
        $this->redis()->hMSet(Keys::forSecret('passwordless', 'bad-digest'), ['code_digest' => 'zz'] + $valid);
        $this->redis()->hMSet(Keys::forSecret('passwordless', 'bad-client'), ['client_id' => 'Not A Client'] + $valid);

        foreach (['bad-mode', 'no-email', 'code-without-digest', 'bad-digest', 'bad-client'] as $handle) {
            self::assertNull($this->challenges()->find($handle), $handle);
        }
        self::assertNull($this->challenges()->claim('bad-mode'));
        self::assertSame(0, $this->redis()->exists(Keys::forSecret('passwordless', 'bad-mode')), 'Claimed anyway.');
    }
}
