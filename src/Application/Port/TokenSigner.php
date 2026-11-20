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
 * Signs tokens, and says which public keys verify them.
 *
 * The port is **sign these bytes**, never **give me the key**. An interface that handed
 * out a private key could only be implemented by backends that let key material into
 * this process, which rules out every non-extractable one — a cloud KMS, Vault Transit,
 * an HSM — and those are the ones worth having: an identity provider's signing key mints
 * valid tokens for any user, and a forgery is indistinguishable from the real thing.
 *
 * So nothing here, and nothing anywhere, loads a private key for a caller. The JWS is
 * assembled by the caller and only its signing input crosses this boundary.
 */
interface TokenSigner
{
    /**
     * The key that signs new tokens: its `kid` goes in the JWS header, which is part of
     * what gets signed, so the caller needs it first.
     *
     * @throws NoActiveSigningKey When there is none. Never answered by creating one: a key that
     *                            appears by accident is one nobody knows to back up or rotate.
     */
    public function activeKey(): SigningKeyReference;

    /**
     * Sign a JWS signing input (RFC 7515 §5.1: `BASE64URL(header) . '.' . BASE64URL(payload)`)
     * with the key `$key` names.
     *
     * @return non-empty-string The raw signature bytes — not base64url-encoded.
     *
     * @throws SigningFailed When that key may no longer sign (it was retired in the meantime) or the
     *                       backend refused.
     */
    #[\NoDiscard]
    public function sign(SigningKeyReference $key, string $signingInput): string;

    /**
     * Every public key a relying party may need: the active one, and each retired one
     * still within its publication window. Built from stored public keys, never by
     * deriving them from private ones. The active key comes first.
     *
     * @return list<PublicJwk>
     */
    public function publicKeys(): array;
}
