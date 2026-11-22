<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Shared\Clock;

/**
 * WebAuthn ceremonies kept in an array, expiring against the clock it is given.
 */
final class InMemoryWebAuthnChallengeStore implements WebAuthnChallengeStore
{
    /** @var array<string, array{challenge: WebAuthnChallenge, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function open(
        #[\SensitiveParameter] string $handle,
        WebAuthnChallenge $challenge,
        int $lifetimeSeconds,
    ): void {
        $this->entries[$handle] = [
            'challenge' => $challenge,
            'expiresAt' => $this->clock->now()->getTimestamp() + $lifetimeSeconds,
        ];
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?WebAuthnChallenge
    {
        $entry = $this->entries[$handle] ?? null;
        unset($this->entries[$handle]);
        if ($entry === null || $entry['expiresAt'] <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        return $entry['challenge'];
    }
}
