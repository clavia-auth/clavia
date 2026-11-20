<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Oidc\PublicJwk;

/**
 * Checks a compact JWS (RFC 7515 §7.1) against public keys, and only that.
 *
 * Signing and verifying are deliberately apart: signing goes through
 * {@see TokenSigner}, which never lets a private key out; verifying needs nothing but
 * the keys this server publishes. What the claims must say — issuer, subject,
 * audience — is the caller's to decide.
 */
interface SignatureVerifier
{
    /**
     * The claims of `$compactJws` when one of `$keys` — the one its `kid` names, with the
     * algorithm that key is for — verifies its signature; null for anything else: a
     * malformed token, an unknown `kid`, another algorithm (`none` included), a bad
     * signature, or a payload that is not a JSON object.
     *
     * @param list<PublicJwk> $keys
     *
     * @return array<string, mixed>|null
     */
    #[\NoDiscard]
    public function verifiedClaims(string $compactJws, array $keys): ?array;
}
