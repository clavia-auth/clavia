<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\DpopReplayCache;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\Shared\Clock;
use DateTimeImmutable;

/**
 * DPoP proofs seen, in memory, forgotten by the clock given.
 */
final class InMemoryDpopReplayCache implements DpopReplayCache
{
    /** @var array<string, DateTimeImmutable> */
    private array $seen = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function claim(JwkThumbprint $key, string $jti, int $ttlSeconds): bool
    {
        $entry = $key->value . "\0" . $jti;
        $now = $this->clock->now();
        if (isset($this->seen[$entry]) && $this->seen[$entry] > $now) {
            return false;
        }
        $this->seen[$entry] = $now->modify(sprintf('+%d seconds', $ttlSeconds));

        return true;
    }
}
