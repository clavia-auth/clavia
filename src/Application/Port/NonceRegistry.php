<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Oidc\Nonce;

/**
 * Remembers which `nonce` values each client has already used, so that one
 * authentication request cannot be answered twice (OIDC Core §15.5.2).
 *
 * The relying party is the one that checks a nonce against its session; this is the
 * server's own defence in depth — a captured authorization URL replayed later must not
 * mint a second code. Short-lived by nature, so it lives in Redis.
 */
interface NonceRegistry
{
    /**
     * Whether `$client` has used `$nonce`. A pure read, for refusing a replay before
     * anybody is asked to sign in for it.
     */
    public function isUsed(ClientId $client, Nonce $nonce): bool;

    /**
     * Mark `$nonce` used by `$client` for `$ttlSeconds`, and say whether this call was the
     * one that did. Atomic: of two concurrent calls, exactly one gets true.
     *
     * @param positive-int $ttlSeconds
     */
    #[\NoDiscard]
    public function claim(ClientId $client, Nonce $nonce, int $ttlSeconds): bool;
}
