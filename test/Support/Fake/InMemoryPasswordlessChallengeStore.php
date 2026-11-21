<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Shared\Clock;

/**
 * Pending passwordless sign-ins kept in an array, expiring against the clock it is given.
 */
final class InMemoryPasswordlessChallengeStore implements PasswordlessChallengeStore
{
    /** @var array<string, array{challenge: PasswordlessChallenge, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function open(
        #[\SensitiveParameter] string $handle,
        PasswordlessChallenge $challenge,
        int $lifetimeSeconds,
    ): void {
        $this->entries[$handle] = [
            'challenge' => $challenge,
            'expiresAt' => $this->clock->now()->getTimestamp() + $lifetimeSeconds,
        ];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge
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
        $this->entries[$handle]['challenge'] = new PasswordlessChallenge(
            $challenge->email,
            $challenge->mode,
            $challenge->codeDigest,
            $challenge->nextUrl,
            $challenge->clientId,
            $challenge->loginState,
            $attempts,
        );

        return true;
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge
    {
        $challenge = $this->find($handle);
        unset($this->entries[$handle]);

        return $challenge;
    }
}
