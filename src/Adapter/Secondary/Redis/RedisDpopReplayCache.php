<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\DpopReplayCache;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;

/**
 * DPoP proofs seen, under `dpop-jti:<digest of the key and the jti>`, set with `NX` so two
 * requests racing with one proof cannot both be the first.
 */
final readonly class RedisDpopReplayCache implements DpopReplayCache
{
    private const string PREFIX = 'dpop-jti';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function claim(JwkThumbprint $key, string $jti, int $ttlSeconds): bool
    {
        // A NUL cannot occur in a thumbprint: the pair is unambiguous.
        $set = $this->redis->client()->set(
            Keys::forSecret(self::PREFIX, $key->value . "\0" . $jti),
            '1',
            ['nx', 'ex' => $ttlSeconds],
        );

        return $set === true;
    }
}
