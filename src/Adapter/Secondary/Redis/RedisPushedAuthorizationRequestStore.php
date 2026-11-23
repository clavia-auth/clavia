<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/**
 * Pushed authorization requests in Redis, under `pushed-request:<digest of the handle>`, for their
 * lifetime. Spent with `DEL`, whose count says which of two racing callers removed it.
 */
final readonly class RedisPushedAuthorizationRequestStore implements PushedAuthorizationRequestStore
{
    private const string PREFIX = 'pushed-request';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function push(
        #[\SensitiveParameter] string $handle,
        PushedAuthorizationRequest $request,
        int $ttlSeconds,
    ): void {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $handle),
            $ttlSeconds,
            json_encode(
                ['client_id' => $request->clientId->value, 'parameters' => $request->parameters],
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            ),
        );
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PushedAuthorizationRequest
    {
        if ($handle === '') {
            return null;
        }
        $raw = $this->redis->client()->get(Keys::forSecret(self::PREFIX, $handle));
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
            /** @var mixed $clientId */
            $clientId = is_array($data) ? ($data['client_id'] ?? null) : null;
            /** @var mixed $parameters */
            $parameters = is_array($data) ? ($data['parameters'] ?? null) : null;
            if (! is_string($clientId) || ! is_array($parameters)) {
                return null;
            }

            $pairs = [];
            /** @var mixed $pair */
            foreach ($parameters as $pair) {
                /** @var mixed $name */
                $name = is_array($pair) ? ($pair[0] ?? null) : null;
                /** @var mixed $value */
                $value = is_array($pair) ? ($pair[1] ?? null) : null;
                if (! is_string($name) || ! is_string($value)) {
                    return null;
                }
                $pairs[] = [$name, $value];
            }

            return new PushedAuthorizationRequest(ClientId::fromString($clientId), $pairs);
        } catch (JsonException | InvalidValue) {
            // An entry this code cannot read is an entry that is not there.
            return null;
        }
    }

    #[\Override]
    public function spend(#[\SensitiveParameter] string $handle): bool
    {
        if ($handle === '') {
            return false;
        }

        return $this->redis->client()->del(Keys::forSecret(self::PREFIX, $handle)) === 1;
    }
}
