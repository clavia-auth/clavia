<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\DpopNonces;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * DPoP nonces in Redis (RFC 9449 §8): a random value per window of `CLAVIA_DPOP_NONCE_LIFETIME`,
 * under `dpop-nonce:<window>`, made by whichever request needs it first (`SET NX`) and kept for
 * two windows, so the previous one is still accepted after the window turns. No key to rotate.
 */
final readonly class RedisDpopNonces implements DpopNonces
{
    private const string PREFIX = 'dpop-nonce';

    /**
     * @param positive-int $windowSeconds
     */
    public function __construct(
        private RedisConnection $redis,
        private SecretGenerator $secrets,
        private Clock $clock,
        private int $windowSeconds,
    ) {
    }

    #[\Override]
    public function current(): string
    {
        return $this->nonceOf($this->window());
    }

    #[\Override]
    public function isCurrent(string $nonce): bool
    {
        if ($nonce === '') {
            return false;
        }
        $window = $this->window();
        $client = $this->redis->client();
        foreach ([$window, $window - 1] as $candidate) {
            $stored = $client->get(Keys::forIdentifier(self::PREFIX, (string) $candidate));
            if (is_string($stored) && hash_equals($stored, $nonce)) {
                return true;
            }
        }

        return false;
    }

    private function window(): int
    {
        return intdiv($this->clock->now()->getTimestamp(), $this->windowSeconds);
    }

    private function nonceOf(int $window): string
    {
        $key = Keys::forIdentifier(self::PREFIX, (string) $window);
        $client = $this->redis->client();
        $client->set($key, $this->secrets->token(), ['nx', 'ex' => $this->windowSeconds * 2]);
        $nonce = $client->get($key);

        return is_string($nonce) ? $nonce : '';
    }
}
