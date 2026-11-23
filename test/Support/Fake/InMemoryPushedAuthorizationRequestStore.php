<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use Clavia\Domain\Shared\Clock;
use DateTimeImmutable;

/**
 * Pushed authorization requests in memory, expiring by the clock given.
 */
final class InMemoryPushedAuthorizationRequestStore implements PushedAuthorizationRequestStore
{
    /** @var array<string, array{PushedAuthorizationRequest, DateTimeImmutable}> */
    private array $requests = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function push(
        #[\SensitiveParameter] string $handle,
        PushedAuthorizationRequest $request,
        int $ttlSeconds,
    ): void {
        $this->requests[$handle] = [$request, $this->clock->now()->modify(sprintf('+%d seconds', $ttlSeconds))];
    }

    #[\Override]
    public function find(#[\SensitiveParameter] string $handle): ?PushedAuthorizationRequest
    {
        $entry = $this->requests[$handle] ?? null;

        return $entry === null || $entry[1] <= $this->clock->now() ? null : $entry[0];
    }

    #[\Override]
    public function spend(#[\SensitiveParameter] string $handle): bool
    {
        if ($this->find($handle) === null) {
            return false;
        }
        unset($this->requests[$handle]);

        return true;
    }
}
