<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc;

use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Shared\Base64Url;

/**
 * Assembles a JWS in compact serialization (RFC 7515 §7.1) — by hand, because no JOSE
 * library signs without holding the private key, and this server never holds it outside
 * the signing backend.
 *
 * `BASE64URL(header) . '.' . BASE64URL(claims)` is the signing input; the backend signs
 * those bytes and nothing else, and the signature is appended. The header names the
 * algorithm and the key (`kid`), which is how a relying party picks the right key from
 * the JWKS after a rotation.
 */
final readonly class CompactJws
{
    public function __construct(private TokenSigner $signer)
    {
    }

    /**
     * @param array<non-empty-string, mixed> $claims
     * @param non-empty-string               $type   The `typ` header (RFC 7515 §4.1.9): `JWT` for an
     *                                               ID token, `logout+jwt` for a logout token,
     *                                               `at+jwt` for an access token (RFC 9068 §2.1).
     *
     * @return non-empty-string
     *
     * @throws SigningFailed
     */
    public function sign(SigningKeyReference $key, array $claims, string $type): string
    {
        $header = ['alg' => $key->algorithm->value, 'typ' => $type, 'kid' => $key->kid];

        $signingInput = Base64Url::encode(self::json($header)) . '.' . Base64Url::encode(self::json($claims));
        $signature = $this->signer->sign($key, $signingInput);

        return $signingInput . '.' . Base64Url::encode($signature);
    }

    /**
     * @param array<array-key, mixed> $value
     */
    private static function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
