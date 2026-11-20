<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Clock;

final class InMemoryNonceRegistry implements NonceRegistry
{
    /** @var array<string, int> Expiry, in seconds since the epoch, by client and nonce. */
    private array $used = [];

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function isUsed(ClientId $client, Nonce $nonce): bool
    {
        return ($this->used[self::key($client, $nonce)] ?? 0) > $this->clock->now()->getTimestamp();
    }

    #[\Override]
    public function claim(ClientId $client, Nonce $nonce, int $ttlSeconds): bool
    {
        if ($this->isUsed($client, $nonce)) {
            return false;
        }

        $this->used[self::key($client, $nonce)] = $this->clock->now()->getTimestamp() + $ttlSeconds;

        return true;
    }

    private static function key(ClientId $client, Nonce $nonce): string
    {
        return $client->value . ':' . $nonce->value;
    }
}
