<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\AttemptCounter;

/**
 * Failure counters in Redis: `login-attempts:<sha256 of the subject>` → an integer whose
 * time-to-live is the window. Hashed so the store never holds an email or an address.
 */
final readonly class RedisAttemptCounter implements AttemptCounter
{
    private const string PREFIX = 'login-attempts';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function count(string $subject): int
    {
        $value = $this->redis->client()->get(Keys::forSecret(self::PREFIX, $subject));

        return is_string($value) && ctype_digit($value) ? (int) $value : 0;
    }

    #[\Override]
    public function increment(string $subject, int $windowSeconds): void
    {
        $key = Keys::forSecret(self::PREFIX, $subject);

        // One transaction: no moment in which the counter exists without an expiry.
        $client = $this->redis->client();
        $client->multi();
        $client->incr($key);
        $client->expire($key, $windowSeconds);
        $client->exec();
    }

    #[\Override]
    public function reset(string ...$subjects): void
    {
        if ($subjects !== []) {
            $this->redis->client()->del(
                array_map(static fn (string $subject): string => Keys::forSecret(self::PREFIX, $subject), $subjects),
            );
        }
    }
}
