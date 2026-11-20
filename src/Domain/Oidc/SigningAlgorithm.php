<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Shared\Base64Url;

/**
 * A JWS algorithm this server signs tokens with (RFC 7518 §3.1).
 *
 * Only RS256 — RSASSA-PKCS1-v1_5 over SHA-256 — so far: it is the algorithm OIDC Core
 * §15.1 makes mandatory to implement, so every relying party can verify what is issued.
 * A new case brings its key type and its hash with it, and nothing else changes.
 */
enum SigningAlgorithm: string
{
    case RS256 = 'RS256';

    /** The JWK key type a key for this algorithm has (RFC 7518 §6.1). */
    public function keyType(): string
    {
        return match ($this) {
            self::RS256 => 'RSA',
        };
    }

    /** The hash the algorithm signs over, as `hash()` names it. */
    public function hashAlgorithm(): string
    {
        return match ($this) {
            self::RS256 => 'sha256',
        };
    }

    /**
     * The "left-most half of the hash" of a token, base64url-encoded: how `at_hash` and
     * `c_hash` bind an ID token to the token issued with it (OIDC Core §3.1.3.6, §3.3.2.11).
     *
     * The hash is the one this algorithm uses — SHA-256 for RS256 — over the ASCII
     * octets of the token exactly as issued.
     */
    public function halfHash(#[\SensitiveParameter] string $token): string
    {
        $digest = hash($this->hashAlgorithm(), $token, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }
}
