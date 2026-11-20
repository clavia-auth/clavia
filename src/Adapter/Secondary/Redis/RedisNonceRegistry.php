<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;

/**
 * Used nonces in Redis: one key per client and nonce, holding nothing, expiring on
 * its own.
 *
 * The key is a digest of `client_id:nonce` (a client id cannot hold a colon, so the
 * pair is unambiguous): the store never keeps a client-supplied value verbatim, and the
 * key length does not depend on what the client sent.
 */
final readonly class RedisNonceRegistry implements NonceRegistry
{
    private const string PREFIX = 'nonce';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function isUsed(ClientId $client, Nonce $nonce): bool
    {
        $exists = $this->redis->client()->exists(self::key($client, $nonce));

        return is_int($exists) && $exists > 0;
    }

    #[\Override]
    public function claim(ClientId $client, Nonce $nonce, int $ttlSeconds): bool
    {
        // SET NX EX: the check and the write are one operation, with the expiry attached.
        return $this->redis->client()->set(self::key($client, $nonce), '1', ['nx', 'ex' => $ttlSeconds]) === true;
    }

    private static function key(ClientId $client, Nonce $nonce): string
    {
        return Keys::forSecret(self::PREFIX, $client->value . ':' . $nonce->value);
    }
}
