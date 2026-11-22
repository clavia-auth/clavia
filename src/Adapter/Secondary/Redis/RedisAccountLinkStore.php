<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Account links in Redis, as a hash under `account-link:<digest of the token>`.
 *
 * The lifetime is set once and never extended. A link is claimed by a Lua script that reads
 * and deletes it in one step, so two requests following the same link cannot both get it.
 */
final readonly class RedisAccountLinkStore implements AccountLinkStore
{
    private const string PREFIX = 'account-link';

    /** KEYS[1] the link. Returns its fields, flat, and deletes it; empty when absent. */
    private const string CLAIM = <<<'LUA'
        local fields = redis.call('HGETALL', KEYS[1])
        redis.call('DEL', KEYS[1])
        return fields
        LUA;

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $token, AccountLink $link, int $lifetimeSeconds): void
    {
        $key = Keys::forSecret(self::PREFIX, $token);
        $client = $this->redis->client();
        $client->multi();
        $client->hMSet($key, [
            'purpose' => $link->purpose->value,
            'user_id' => $link->userId->toString(),
            'email' => $link->email,
            'login_state' => $link->loginState ?? '',
            'password_fingerprint' => $link->passwordFingerprint?->toString() ?? '',
        ]);
        $client->expire($key, $lifetimeSeconds);
        $client->exec();
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $token): ?AccountLink
    {
        if ($token === '') {
            return null;
        }
        /** @var array<string, string>|false $fields */
        $fields = $this->redis->client()->hGetAll(Keys::forSecret(self::PREFIX, $token));

        return is_array($fields) ? self::link($fields) : null;
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $token): ?AccountLink
    {
        if ($token === '') {
            return null;
        }
        /** @var mixed $flat */
        $flat = $this->redis->client()->eval(self::CLAIM, [Keys::forSecret(self::PREFIX, $token)], 1);
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

        return self::link($fields);
    }

    /**
     * The link the stored fields describe; null for none, or for an entry this code cannot
     * read — which is an entry that is not there.
     *
     * @param array<string, string> $fields
     */
    private static function link(array $fields): ?AccountLink
    {
        $purpose = AccountLinkPurpose::tryFrom($fields['purpose'] ?? '');
        $email = $fields['email'] ?? '';
        if ($purpose === null || $email === '') {
            return null;
        }
        try {
            $fingerprint = ($fields['password_fingerprint'] ?? '') === ''
                ? null
                : Digest::fromHex($fields['password_fingerprint']);
            $userId = UserId::fromString($fields['user_id'] ?? '');
        } catch (InvalidValue) {
            return null;
        }
        if (($purpose === AccountLinkPurpose::ResetPassword) !== ($fingerprint !== null)) {
            return null;
        }
        $loginState = $fields['login_state'] ?? '';

        return AccountLink::reconstitute(
            $purpose,
            $userId,
            $email,
            $loginState === '' ? null : $loginState,
            $fingerprint,
        );
    }
}
