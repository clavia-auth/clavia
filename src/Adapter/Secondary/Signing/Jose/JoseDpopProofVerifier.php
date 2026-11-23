<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Jose;

use Clavia\Application\Port\DpopProofVerifier;
use Clavia\Domain\OAuth2\Dpop\DpopAlgorithm;
use Clavia\Domain\OAuth2\Dpop\DpopProof;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use DateTimeImmutable;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Throwable;

/**
 * {@see DpopProofVerifier} on `web-token/jwt-library` (RFC 9449 §4.3 steps 2–8): verification
 * only, the library's allowed use here.
 *
 * The key is the one the proof carries (`jwk`), and must be what the `alg` needs — an EC P-256
 * key for ES256, an Ed25519 key for EdDSA, an RSA key of at least 2048 bits for RS256 —
 * so a proof claiming another algorithm than its key's finds nothing to verify with. A `jwk` with
 * a private member is refused, never trusted. Only the algorithms of {@see DpopAlgorithm} exist
 * here: `none` and MACs are not refused, they are absent.
 */
final readonly class JoseDpopProofVerifier implements DpopProofVerifier
{
    private const array PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    #[\Override]
    public function verify(string $proof): ?DpopProof
    {
        try {
            $jws = new CompactSerializer()->unserialize($proof);
            if ($jws->countSignatures() !== 1) {
                return null;
            }
            $header = $jws->getSignature(0)->getProtectedHeader();
            /** @var mixed $alg */
            $alg = $header['alg'] ?? null;
            $algorithm = DpopAlgorithm::tryFrom(is_string($alg) ? $alg : '');
            /** @var mixed $members */
            $members = $header['jwk'] ?? null;
            if (($header['typ'] ?? null) !== 'dpop+jwt' || $algorithm === null || ! is_array($members)) {
                return null;
            }
            if (array_intersect(array_keys($members), self::PRIVATE_MEMBERS) !== []) {
                return null;
            }
            /** @var array<string, mixed> $members */
            $jwk = new JWK($members);
            if (! self::fits($jwk, $algorithm)) {
                return null;
            }

            $verifier = new JWSVerifier(new AlgorithmManager([self::algorithm($algorithm)]));
            if (! $verifier->verifyWithKey($jws, $jwk, 0)) {
                return null;
            }

            /** @var mixed $claims */
            $claims = json_decode((string) $jws->getPayload(), true, 8, JSON_THROW_ON_ERROR);

            return is_array($claims) ? self::proof($claims, $algorithm, $jwk) : null;
        } catch (Throwable) {
            // The library throws on anything it cannot parse: a proof that does not verify.
            return null;
        }
    }

    /** Whether the key is of the type the algorithm signs with. */
    private static function fits(JWK $jwk, DpopAlgorithm $algorithm): bool
    {
        /** @var mixed $modulus */
        $modulus = $jwk->has('n') ? $jwk->get('n') : null;

        return match ($algorithm) {
            DpopAlgorithm::ES256 => $jwk->get('kty') === 'EC' && $jwk->get('crv') === 'P-256',
            DpopAlgorithm::EdDSA => $jwk->get('kty') === 'OKP' && $jwk->get('crv') === 'Ed25519',
            DpopAlgorithm::RS256 => $jwk->get('kty') === 'RSA'
                && is_string($modulus)
                && strlen(self::base64UrlDecode($modulus)) >= 256,
        };
    }

    private static function algorithm(DpopAlgorithm $algorithm): ES256|EdDSA|RS256
    {
        return match ($algorithm) {
            DpopAlgorithm::ES256 => new ES256(),
            DpopAlgorithm::EdDSA => new EdDSA(),
            DpopAlgorithm::RS256 => new RS256(),
        };
    }

    /**
     * The claims of §4.2: `jti`, `htm`, `htu` and `iat` required; `ath` and `nonce` when present.
     *
     * @param array<array-key, mixed> $claims
     */
    private static function proof(array $claims, DpopAlgorithm $algorithm, JWK $jwk): ?DpopProof
    {
        $jti = $claims['jti'] ?? null;
        $htm = $claims['htm'] ?? null;
        $htu = $claims['htu'] ?? null;
        $iat = $claims['iat'] ?? null;
        $ath = $claims['ath'] ?? null;
        $nonce = $claims['nonce'] ?? null;
        if (
            ! is_string($jti) || $jti === '' || strlen($jti) > 256
            || ! is_string($htm) || $htm === ''
            || ! is_string($htu) || $htu === ''
            || ! is_int($iat)
            || ($ath !== null && (! is_string($ath) || $ath === ''))
            || ($nonce !== null && ! is_string($nonce))
        ) {
            return null;
        }

        return new DpopProof(
            JwkThumbprint::fromString($jwk->thumbprint('sha256')),
            $algorithm,
            $htm,
            $htu,
            new DateTimeImmutable('@' . $iat),
            $jti,
            $ath,
            $nonce,
        );
    }

    private static function base64UrlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }
}
