<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Dpop;

use DateTimeImmutable;

/**
 * What a DPoP proof says (RFC 9449 §4.2), once its signature verified against the key it carries:
 * which key made it, for which request, when, under which unique id, and — when presented with a
 * token or asked for one — the token's hash and the server's nonce.
 *
 * Built only by the verifier, which has checked everything cryptographic (`typ`, `alg`, the
 * `jwk`, the signature). Whether the proof is for *this* request is {@see ProofRequirement}'s.
 */
final readonly class DpopProof
{
    /**
     * @param non-empty-string      $method          `htm`.
     * @param non-empty-string      $url             `htu`.
     * @param non-empty-string      $jti
     * @param non-empty-string|null $accessTokenHash `ath`: base64url SHA-256 of the access token.
     */
    public function __construct(
        public JwkThumbprint $thumbprint,
        public DpopAlgorithm $algorithm,
        public string $method,
        public string $url,
        public DateTimeImmutable $issuedAt,
        public string $jti,
        public ?string $accessTokenHash = null,
        public ?string $nonce = null,
    ) {
    }
}
