<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\SessionStore;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\Clock;

/**
 * Sessions kept in an array, each expiring against the clock it is given, as a key with
 * a time-to-live would.
 */
final class InMemorySessionStore implements SessionStore
{
    /** @var array<string, array{session: Session, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function save(#[\SensitiveParameter] string $sessionId, Session $session, int $ttlSeconds): void
    {
        $this->entries[$sessionId] = ['session' => $session, 'expiresAt' => $this->now() + $ttlSeconds];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $sessionId): ?Session
    {
        return $this->live($sessionId)['session'] ?? null;
    }

    #[\Override]
    public function extend(#[\SensitiveParameter] string $sessionId, int $ttlSeconds): void
    {
        $entry = $this->live($sessionId);
        if ($entry !== null) {
            $this->entries[$sessionId] = ['session' => $entry['session'], 'expiresAt' => $this->now() + $ttlSeconds];
        }
    }

    #[\Override]
    public function delete(#[\SensitiveParameter] string $sessionId): void
    {
        unset($this->entries[$sessionId]);
    }

    /** Seconds the entry has left; null when it is gone. For assertions. */
    public function ttl(string $sessionId): ?int
    {
        $entry = $this->live($sessionId);

        return $entry === null ? null : $entry['expiresAt'] - $this->now();
    }

    public function count(): int
    {
        return count(array_filter($this->entries, fn (array $entry): bool => $entry['expiresAt'] > $this->now()));
    }

    /**
     * @return array{session: Session, expiresAt: int}|null
     */
    private function live(string $sessionId): ?array
    {
        $entry = $this->entries[$sessionId] ?? null;

        return $entry !== null && $entry['expiresAt'] > $this->now() ? $entry : null;
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }
}
