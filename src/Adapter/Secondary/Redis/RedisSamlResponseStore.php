<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\Saml\ParkedSamlResponse;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use JsonException;

/** Parked SAML responses, by the digest of their handle, claimed with `GETDEL`. */
final readonly class RedisSamlResponseStore implements SamlResponseStore
{
    private const string PREFIX = 'saml-response';

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function park(#[\SensitiveParameter] string $handle, ParkedSamlResponse $response): void
    {
        $this->redis->client()->setex(
            Keys::forSecret(self::PREFIX, $handle),
            SamlResponseStore::TTL_SECONDS,
            json_encode([
                'connection' => $response->connection->value,
                'response' => $response->response,
                'relay_state' => $response->relayState,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        );
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?ParkedSamlResponse
    {
        if ($handle === '') {
            return null;
        }
        /** @var mixed $raw */
        $raw = $this->redis->client()->getDel(Keys::forSecret(self::PREFIX, $handle));
        if (! is_string($raw)) {
            return null;
        }
        try {
            /** @var mixed $data */
            $data = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
            if (! is_array($data)) {
                return null;
            }
            /** @var mixed $connection */
            $connection = $data['connection'] ?? null;
            /** @var mixed $response */
            $response = $data['response'] ?? null;
            /** @var mixed $relayState */
            $relayState = $data['relay_state'] ?? null;
            if (! is_string($connection) || ! is_string($response) || ! is_string($relayState)) {
                return null;
            }

            return new ParkedSamlResponse(ConnectionName::fromString($connection), $response, $relayState);
        } catch (JsonException | InvalidValue) {
            return null;
        }
    }
}
