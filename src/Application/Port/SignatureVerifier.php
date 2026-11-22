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
     * The claims of `$compactJws` when its protected header's `typ` is `$type` and one of
     * `$keys` — the one its `kid` names, with the algorithm that key is for — verifies its
     * signature; null for anything else: another type, a malformed token, an unknown `kid`,
     * another algorithm (`none` included), a bad signature, or a payload that is not a JSON
     * object.
     *
     * The type is required because every token this server signs — ID tokens, logout tokens,
     * JWT access tokens — is signed with the same keys and can carry the same `iss` and `sub`:
     * only the header tells one kind from another (explicit typing, RFC 8725 §3.11). It is
     * compared exactly, since the only tokens verified here are this server's own.
     *
     * @param list<PublicJwk>  $keys
     * @param non-empty-string $type The `typ` the token must carry (RFC 7515 §4.1.9).
     *
     * @return array<string, mixed>|null
     */
    #[\NoDiscard]
    public function verifiedClaims(string $compactJws, array $keys, string $type): ?array;
}
