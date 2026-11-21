<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Shared\Clock;

/**
 * Requests on hold for the consent screen, kept in an array and expiring against the
 * clock it is given.
 */
final class InMemoryConsentStateStore implements ConsentStateStore
{
    /** @var array<string, array{pending: PendingConsent, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function park(#[\SensitiveParameter] string $handle, PendingConsent $pending): void
    {
        $this->entries[$handle] = [
            'pending' => $pending,
            'expiresAt' => $this->clock->now()->getTimestamp() + PendingConsent::LIFETIME_SECONDS,
        ];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PendingConsent
    {
        $entry = $this->entries[$handle] ?? null;

        return $entry !== null && $entry['expiresAt'] > $this->clock->now()->getTimestamp() ? $entry['pending'] : null;
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?PendingConsent
    {
        $pending = $this->find($handle);
        unset($this->entries[$handle]);

        return $pending;
    }

    public function count(): int
    {
        return count($this->entries);
    }
}
