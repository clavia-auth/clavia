<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\DpopNonces;
use Clavia\Domain\Shared\Clock;

/**
 * DPoP nonces in memory: one per window of the clock given, the previous one still accepted.
 */
final class InMemoryDpopNonces implements DpopNonces
{
    /** @var array<int, string> */
    private array $byWindow = [];

    /**
     * @param positive-int $windowSeconds
     */
    public function __construct(private readonly Clock $clock, private readonly int $windowSeconds = 300)
    {
    }

    #[\Override]
    public function current(): string
    {
        $window = $this->window();

        return $this->byWindow[$window] ??= 'nonce-' . $window . '-' . bin2hex(random_bytes(8));
    }

    #[\Override]
    public function isCurrent(string $nonce): bool
    {
        $window = $this->window();

        $accepted = [$this->byWindow[$window] ?? null, $this->byWindow[$window - 1] ?? null];

        return $nonce !== '' && in_array($nonce, $accepted, true);
    }

    private function window(): int
    {
        return intdiv($this->clock->now()->getTimestamp(), $this->windowSeconds);
    }
}
