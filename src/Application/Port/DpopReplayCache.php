<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;

/**
 * The `jti` of every DPoP proof accepted, per key, for as long as the proof could still be
 * accepted (RFC 9449 §11.1): a proof is good once.
 */
interface DpopReplayCache
{
    /**
     * Record the proof, atomically: true for the first time it is seen, false for a replay.
     *
     * @param positive-int $ttlSeconds
     */
    #[\NoDiscard]
    public function claim(JwkThumbprint $key, string $jti, int $ttlSeconds): bool;
}
