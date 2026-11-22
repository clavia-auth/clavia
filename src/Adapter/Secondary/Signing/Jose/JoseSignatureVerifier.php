<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Jose;

use Clavia\Application\Port\SignatureVerifier;
use Clavia\Domain\Oidc\PublicJwk;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Throwable;

/**
 * {@see SignatureVerifier} on `web-token/jwt-library`: verification only, the use the
 * library is allowed here (it never signs — see "Signing keys" in CLAUDE.md).
 *
 * The key is chosen by the token's `kid` among the keys given, and the algorithm is the
 * key's own, never the header's: a token claiming `none`, or HS256 with the public key
 * as the secret, finds no key to match. A token of another type than the one asked for
 * is refused before any key is looked at (RFC 8725 §3.11).
 */
final readonly class JoseSignatureVerifier implements SignatureVerifier
{
    #[\Override]
    public function verifiedClaims(string $compactJws, array $keys, string $type): ?array
    {
        try {
            $jws = new CompactSerializer()->unserialize($compactJws);
            if ($jws->countSignatures() !== 1) {
                return null;
            }
            $header = $jws->getSignature(0)->getProtectedHeader();
            if (($header['typ'] ?? null) !== $type) {
                return null;
            }
            /** @var mixed $kid */
            $kid = $header['kid'] ?? null;
            /** @var mixed $algorithm */
            $algorithm = $header['alg'] ?? null;
            $key = array_find($keys, static fn (PublicJwk $jwk): bool => $jwk->kid === $kid);
            if ($key === null || $algorithm !== $key->algorithm->value) {
                return null;
            }

            $verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
            if (! $verifier->verifyWithKey($jws, new JWK($key->toArray()), 0)) {
                return null;
            }

            /** @var mixed $claims */
            $claims = json_decode((string) $jws->getPayload(), true, 16, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            // The library throws on anything it cannot parse: a token that does not verify.
            return null;
        }

        // A JSON object (RFC 7519 §7.2): `{}` decodes to an empty array, `[1]` to a list.
        if (! is_array($claims) || ($claims !== [] && array_is_list($claims))) {
            return null;
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }
}
