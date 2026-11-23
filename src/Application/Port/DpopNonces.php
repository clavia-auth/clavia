<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * The nonces this server provides for DPoP proofs (RFC 9449 §8): one per window, the current and
 * the previous one accepted, so a nonce handed out just before the window turns still works.
 */
interface DpopNonces
{
    /** The nonce to hand out now: what `DPoP-Nonce` carries. */
    public function current(): string;

    /** Whether a proof's nonce is the current one or the one before it. */
    public function isCurrent(string $nonce): bool;
}
