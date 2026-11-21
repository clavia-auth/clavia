<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Adapter\Secondary\Signing\Remote\PublicKeyCache;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * Remote signing keys' public halves in Redis, under `signing-public-key:<digest>` — of the
 * algorithm and the reference, which names an account, a project or a vault and is
 * nobody's business in a key listing.
 *
 * They expire after a day although they never change: only so that keys nobody uses any
 * more do not stay forever. What is read back is checked again as any published key is
 * ({@see PublicJwk::fromArray()}); an entry that fails is a miss.
 */
final readonly class RedisPublicKeyCache implements PublicKeyCache
{
    public const int TTL = 86_400;

    private const string PREFIX = 'signing-public-key';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function get(string $reference, SigningAlgorithm $algorithm): ?PublicJwk
    {
        /** @var mixed $stored */
        $stored = $this->redis->client()->get(self::key($reference, $algorithm));
        if (! is_string($stored)) {
            return null;
        }

        try {
            /** @var mixed $jwk */
            $jwk = json_decode($stored, true, 4, JSON_THROW_ON_ERROR);

            return is_array($jwk) ? PublicJwk::fromArray($jwk) : null;
        } catch (JsonException | InvalidValue) {
            return null;
        }
    }

    #[\Override]
    public function put(string $reference, PublicJwk $key): void
    {
        $this->redis->client()->setex(
            self::key($reference, $key->algorithm),
            self::TTL,
            json_encode($key->toArray(), JSON_THROW_ON_ERROR),
        );
    }

    private static function key(string $reference, SigningAlgorithm $algorithm): string
    {
        return Keys::forIdentifier(self::PREFIX, Digest::of($algorithm->value . ' ' . $reference)->toString());
    }
}
