<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Domain\Connection\ConnectionName;

/** Accepted assertion ids, `SET NX EX`, by the digest of the connection and the id. */
final readonly class RedisSamlAssertionReplayCache implements SamlAssertionReplayCache
{
    private const string PREFIX = 'saml-assertion';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function claimAssertion(ConnectionName $connection, string $assertionId, int $ttlSeconds): bool
    {
        // A NUL cannot occur in a connection name: the pair is unambiguous.
        return $this->redis->client()->set(
            Keys::forSecret(self::PREFIX, $connection->value . "\0" . $assertionId),
            '1',
            ['nx', 'ex' => $ttlSeconds],
        ) === true;
    }
}
