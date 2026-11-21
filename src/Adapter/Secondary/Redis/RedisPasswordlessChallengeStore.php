<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Authentication\PasswordlessMode;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use ValueError;

/**
 * Pending passwordless sign-ins in Redis, as a hash under `passwordless:<digest of the
 * handle>`.
 *
 * The lifetime is set once and never extended. Wrong codes are counted, and a challenge
 * claimed, by Lua scripts: a burst of concurrent guesses is counted exactly, two requests
 * spending the same link cannot both get it, and a challenge that expired in between is
 * not brought back to life without a TTL.
 */
final readonly class RedisPasswordlessChallengeStore implements PasswordlessChallengeStore
{
    private const string PREFIX = 'passwordless';

    /**
     * KEYS[1] the challenge, ARGV[1] the limit. Returns 1 if the challenge survives,
     * 0 if it was destroyed or did not exist. HINCRBY leaves the TTL as it was.
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

    /** KEYS[1] the challenge. Returns its fields, flat, and deletes it; empty when absent. */
    private const string CLAIM = <<<'LUA'
        local fields = redis.call('HGETALL', KEYS[1])
        redis.call('DEL', KEYS[1])
        return fields
        LUA;

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function open(
        #[\SensitiveParameter] string $handle,
        PasswordlessChallenge $challenge,
        int $lifetimeSeconds,
    ): void {
        $key = Keys::forSecret(self::PREFIX, $handle);
        $client = $this->redis->client();
        $client->multi();
        $client->hMSet($key, [
            'email' => $challenge->email,
            'mode' => $challenge->mode->value,
            'code_digest' => $challenge->codeDigest?->toString() ?? '',
            'next_url' => $challenge->nextUrl,
            'client_id' => $challenge->clientId->value ?? '',
            'login_state' => $challenge->loginState ?? '',
            'attempts' => (string) $challenge->attempts,
        ]);
        $client->expire($key, $lifetimeSeconds);
        $client->exec();
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge
    {
        if ($handle === '') {
            return null;
        }

        /** @var array<string, string>|false $fields */
        $fields = $this->redis->client()->hGetAll(Keys::forSecret(self::PREFIX, $handle));

        return is_array($fields) ? self::challenge($fields) : null;
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
    public function claim(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge
    {
        if ($handle === '') {
            return null;
        }

        /** @var mixed $flat */
        $flat = $this->redis->client()->eval(self::CLAIM, [Keys::forSecret(self::PREFIX, $handle)], 1);
        if (! is_array($flat)) {
            return null;
        }

        // HGETALL inside a script answers as a flat list: field, value, field, value.
        $fields = [];
        foreach (array_chunk($flat, 2) as $pair) {
            if (count($pair) === 2 && is_string($pair[0]) && is_string($pair[1])) {
                $fields[$pair[0]] = $pair[1];
            }
        }

        return self::challenge($fields);
    }

    /**
     * The challenge the stored fields describe; null for none, or for an entry this code
     * cannot read — which is an entry that is not there.
     *
     * @param array<string, string> $fields
     */
    private static function challenge(array $fields): ?PasswordlessChallenge
    {
        $text = static fn (string $name): string => $fields[$name] ?? '';

        $email = $text('email');
        $mode = PasswordlessMode::tryFrom($text('mode'));
        if ($email === '' || $mode === null || $text('next_url') === '') {
            return null;
        }

        try {
            return new PasswordlessChallenge(
                $email,
                $mode,
                $text('code_digest') === '' ? null : Digest::fromHex($text('code_digest')),
                $text('next_url'),
                $text('client_id') === '' ? null : ClientId::fromString($text('client_id')),
                $text('login_state') === '' ? null : $text('login_state'),
                max(0, (int) $text('attempts')),
            );
        } catch (InvalidValue | ValueError) {
            return null;
        }
    }
}
