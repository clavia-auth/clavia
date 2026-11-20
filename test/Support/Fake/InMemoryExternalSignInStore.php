<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Shared\Clock;

/**
 * Pending external sign-ins kept in an array, expiring against the clock it is given.
 */
final class InMemoryExternalSignInStore implements ExternalSignInStore
{
    /** @var array<string, array{pending: PendingExternalSignIn, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $handle, PendingExternalSignIn $pending): void
    {
        $this->entries[$handle] = [
            'pending' => $pending,
            'expiresAt' => $this->clock->now()->getTimestamp() + PendingExternalSignIn::LIFETIME_SECONDS,
        ];
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?PendingExternalSignIn
    {
        $entry = $this->entries[$handle] ?? null;
        unset($this->entries[$handle]);

        return $entry !== null && $entry['expiresAt'] > $this->clock->now()->getTimestamp() ? $entry['pending'] : null;
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
