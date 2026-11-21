<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Shared\Clock;

/**
 * Pending second steps kept in an array, expiring against the clock it is given.
 */
final class InMemoryMfaChallengeStore implements MfaChallengeStore
{
    /** @var array<string, array{challenge: MfaChallenge, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $handle, MfaChallenge $challenge, int $lifetimeSeconds): void
    {
        $this->entries[$handle] = [
            'challenge' => $challenge,
            'expiresAt' => $this->clock->now()->getTimestamp() + $lifetimeSeconds,
        ];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?MfaChallenge
    {
        $entry = $this->entries[$handle] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry['expiresAt'] <= $this->clock->now()->getTimestamp()) {
            unset($this->entries[$handle]);

            return null;
        }

        return $entry['challenge'];
    }

    #[\Override]
    public function recordFailure(#[\SensitiveParameter] string $handle, int $maxAttempts): bool
    {
        $challenge = $this->find($handle);
        if ($challenge === null) {
            return false;
        }
        $attempts = $challenge->attempts + 1;
        if ($attempts >= $maxAttempts) {
            unset($this->entries[$handle]);

            return false;
        }
        $this->entries[$handle]['challenge'] = new MfaChallenge(
            $challenge->userId,
            $challenge->nextUrl,
            $challenge->clientId,
            $challenge->firstFactor,
            $challenge->connection,
            $attempts,
        );

        return true;
    }

    #[\Override]
    public function close(#[\SensitiveParameter] string $handle): void
    {
        unset($this->entries[$handle]);
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
