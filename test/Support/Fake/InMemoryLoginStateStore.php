<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Shared\Clock;

/**
 * Pending sign-ins kept in an array, expiring against the clock it is given.
 */
final class InMemoryLoginStateStore implements LoginStateStore
{
    /** @var array<string, array{state: LoginState, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function put(#[\SensitiveParameter] string $handle, LoginState $state): void
    {
        $this->entries[$handle] = [
            'state' => $state,
            'expiresAt' => $this->clock->now()->getTimestamp() + LoginState::LIFETIME_SECONDS,
        ];
    }

    #[\Override]
    public function get(#[\SensitiveParameter] string $handle): ?LoginState
    {
        $entry = $this->entries[$handle] ?? null;

        return $entry !== null && $entry['expiresAt'] > $this->clock->now()->getTimestamp() ? $entry['state'] : null;
    }

    #[\Override]
    public function forget(#[\SensitiveParameter] string $handle): void
    {
        unset($this->entries[$handle]);
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
