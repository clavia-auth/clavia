<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\AttemptCounter;
use Clavia\Domain\Shared\Clock;

/**
 * Failure counters kept in an array, each expiring against the clock it is given.
 */
final class InMemoryAttemptCounter implements AttemptCounter
{
    /** @var array<string, array{count: int, expiresAt: int}> */
    private array $counters = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function count(string $subject): int
    {
        $counter = $this->counters[$subject] ?? null;

        return $counter !== null && $counter['expiresAt'] > $this->now() ? $counter['count'] : 0;
    }

    #[\Override]
    public function increment(string $subject, int $windowSeconds): void
    {
        $this->counters[$subject] = [
            'count' => $this->count($subject) + 1,
            'expiresAt' => $this->now() + $windowSeconds,
        ];
    }

    #[\Override]
    public function reset(string ...$subjects): void
    {
        foreach ($subjects as $subject) {
            unset($this->counters[$subject]);
        }
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
