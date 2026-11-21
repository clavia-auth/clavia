<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Adapter\Secondary\IdentityProvider\JwksCache;
use Clavia\Domain\Shared\Digest;

/**
 * Upstream providers' key sets in Redis, under `oidc-jwks:<digest of the URI>` — digested
 * to keep the key short, not because the URI is a secret.
 */
final readonly class RedisJwksCache implements JwksCache
{
    private const string PREFIX = 'oidc-jwks';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function get(string $jwksUri): ?string
    {
        /** @var mixed $document */
        $document = $this->redis->client()->get(self::key($jwksUri));

        return is_string($document) ? $document : null;
    }

    #[\Override]
    public function put(string $jwksUri, string $document, int $ttlSeconds): void
    {
        $this->redis->client()->setex(self::key($jwksUri), $ttlSeconds, $document);
    }

    private static function key(string $jwksUri): string
    {
        return Keys::forIdentifier(self::PREFIX, Digest::of($jwksUri)->toString());
    }
}
