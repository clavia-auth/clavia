<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLink;
use Clavia\Domain\Shared\Clock;

/**
 * Account links kept in an array, expiring against the clock it is given.
 */
final class InMemoryAccountLinkStore implements AccountLinkStore
{
    /** @var array<string, array{link: AccountLink, expiresAt: int}> */
    private array $entries = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function open(#[\SensitiveParameter] string $token, AccountLink $link, int $lifetimeSeconds): void
    {
        $this->entries[$token] = [
            'link' => $link,
            'expiresAt' => $this->clock->now()->getTimestamp() + $lifetimeSeconds,
        ];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $token): ?AccountLink
    {
        $entry = $this->entries[$token] ?? null;
        if ($entry === null) {
            return null;
        }
        if ($entry['expiresAt'] <= $this->clock->now()->getTimestamp()) {
            unset($this->entries[$token]);

            return null;
        }

        return $entry['link'];
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $token): ?AccountLink
    {
        $link = $this->find($token);
        unset($this->entries[$token]);

        return $link;
    }

    /**
     * The tokens of the links open now, oldest first: how a test follows the link a use case
     * mailed without parsing the mail.
     *
     * @return list<string>
     */
    public function tokens(): array
    {
        return array_map('strval', array_keys($this->entries));
    }
}
