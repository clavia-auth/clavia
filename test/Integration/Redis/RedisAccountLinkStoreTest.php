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
use Clavia\Adapter\Secondary\Redis\RedisAccountLinkStore;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use ClaviaTest\Support\Contract\AccountLinkStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use DateTimeImmutable;

final class RedisAccountLinkStoreTest extends IntegrationTestCase
{
    use AccountLinkStoreContract;

    #[\Override]
    protected function links(): AccountLinkStore
    {
        return new RedisAccountLinkStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testALinkLivesForItsLifetimeAndItsTokenIsNotStored(): void
    {
        $this->links()->open('the-plain-token', AccountLink::verifyEmail(self::jane(), null), 900);

        $key = Keys::forSecret('account-link', 'the-plain-token');
        self::assertGreaterThan(895, $this->redis()->ttl($key));
        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        self::assertStringNotContainsString('the-plain-token', implode('|', $keys));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $valid = [
            'purpose' => 'verify_email',
            'user_id' => '6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f',
            'email' => 'jane@example.com',
            'login_state' => '',
            'password_fingerprint' => '',
        ];
        $broken = [
            'bad-purpose' => ['purpose' => 'unlock'] + $valid,
            'no-email' => ['email' => ''] + $valid,
            'bad-user' => ['user_id' => 'nobody'] + $valid,
            'reset-without-fingerprint' => ['purpose' => 'reset_password'] + $valid,
            'bad-fingerprint' => ['purpose' => 'reset_password', 'password_fingerprint' => 'zz'] + $valid,
        ];
        foreach ($broken as $token => $fields) {
            $this->redis()->hMSet(Keys::forSecret('account-link', $token), $fields);
            self::assertNull($this->links()->find($token), $token);
        }
        self::assertNull($this->links()->claim('bad-purpose'));
        self::assertSame(0, $this->redis()->exists(Keys::forSecret('account-link', 'bad-purpose')), 'Claimed anyway.');
    }

    private static function jane(): User
    {
        return User::register(
            UserId::fromString('6f1d6f0e-6b2a-4c9e-9d8a-3b1f2c4d5e6f'),
            'jane@example.com',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
