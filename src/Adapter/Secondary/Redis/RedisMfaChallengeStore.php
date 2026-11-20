<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;
use ValueError;

/**
 * Pending second steps in Redis, as a hash under `mfa-challenge:<digest of the handle>`.
 *
 * The lifetime is set once, when the challenge opens, and never extended: the window is
 * for finishing this sign-in, not for keeping a half-started one alive by guessing at
 * it. Wrong answers are counted by a Lua script, so a burst of concurrent guesses is
 * counted exactly and cannot get past the limit, and a challenge that expired between
 * reading it and counting is not brought back to life without a TTL.
 */
final readonly class RedisMfaChallengeStore implements MfaChallengeStore
{
    private const string PREFIX = 'mfa-challenge';

    /**
     * KEYS[1] the challenge, ARGV[1] the limit. Returns 1 if the challenge survives,
     * 0 if it was destroyed or did not exist.
     */
    private const string RECORD_FAILURE = <<<'LUA'
        if redis.call('EXISTS', KEYS[1]) == 0 then
            return 0
        end
        local attempts = redis.call('HINCRBY', KEYS[1], 'attempts', 1)
        if attempts >= tonumber(ARGV[1]) then
            redis.call('DEL', KEYS[1])
            return 0
        end
        return 1
        LUA;

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $handle, MfaChallenge $challenge, int $lifetimeSeconds): void
    {
        $key = Keys::forSecret(self::PREFIX, $handle);
        $client = $this->redis->client();
        $client->multi();
        $client->hMSet($key, [
            'user_id' => $challenge->userId->value,
            'next_url' => $challenge->nextUrl,
            'client_id' => $challenge->clientId->value ?? '',
            'amr' => json_encode(
                array_map(static fn (AuthenticationMethod $method): string => $method->value, $challenge->firstFactor),
                JSON_THROW_ON_ERROR,
            ),
            'attempts' => (string) $challenge->attempts,
        ]);
        $client->expire($key, $lifetimeSeconds);
        $client->exec();
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?MfaChallenge
    {
        if ($handle === '') {
            return null;
        }

        /** @var array<string, string>|false $fields */
        $fields = $this->redis->client()->hGetAll(Keys::forSecret(self::PREFIX, $handle));
        if (! is_array($fields) || $fields === []) {
            return null;
        }

        try {
            /** @var mixed $methods */
            $methods = json_decode($fields['amr'] ?? '', true, flags: JSON_THROW_ON_ERROR);
            if (! is_array($methods) || ! isset($fields['user_id'], $fields['next_url'])) {
                return null;
            }

            return new MfaChallenge(
                UserId::fromString($fields['user_id']),
                $fields['next_url'],
                ($fields['client_id'] ?? '') === '' ? null : ClientId::fromString($fields['client_id']),
                array_values(array_map(
                    static fn (mixed $method): AuthenticationMethod => AuthenticationMethod::from(
                        is_string($method) ? $method : '',
                    ),
                    $methods,
                )),
                max(0, (int) ($fields['attempts'] ?? '0')),
            );
        } catch (JsonException | InvalidValue | ValueError) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }

    #[\Override]
    public function recordFailure(#[\SensitiveParameter] string $handle, int $maxAttempts): bool
    {
        if ($handle === '') {
            return false;
        }

        /** @var mixed $survives */
        $survives = $this->redis->client()->eval(
            self::RECORD_FAILURE,
            [Keys::forSecret(self::PREFIX, $handle), (string) $maxAttempts],
            1,
        );

        return $survives === 1;
    }

    #[\Override]
    public function close(#[\SensitiveParameter] string $handle): void
    {
        if ($handle !== '') {
            $this->redis->client()->del(Keys::forSecret(self::PREFIX, $handle));
        }
    }
}
