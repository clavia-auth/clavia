<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Reads the X.509 `SubjectPublicKeyInfo` a provider hands back — DER from AWS KMS, PEM
 * from Google Cloud KMS — into the JWK this server publishes.
 *
 * Refuses anything but an RSA key of at least 2048 bits (RFC 7518 §3.3): a provider
 * misconfigured into an elliptic-curve or a short key is reported where it is read, not
 * by the relying parties that cannot verify it.
 */
final class SubjectPublicKeyInfo
{
    public const int MINIMUM_RSA_BITS = 2048;

    private const string PEM = "-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n";

    private function __construct()
    {
    }

    /**
     * @param string $encoded DER bytes, or PEM text.
     *
     * @throws SigningFailed
     */
    public static function toJwk(string $encoded, SigningAlgorithm $algorithm): PublicJwk
    {
        $pem = str_starts_with(ltrim($encoded), '-----BEGIN ')
            ? $encoded
            : sprintf(self::PEM, chunk_split(base64_encode($encoded), 64, "\n"));

        $key = openssl_pkey_get_public($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($details === false) {
            throw new SigningFailed('The signing service returned a public key that cannot be read.');
        }

        /** @var array{bits: int, type: int, rsa?: array{n?: string, e?: string}} $details */
        if ($details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < self::MINIMUM_RSA_BITS) {
            throw new SigningFailed(sprintf(
                'The signing key must be an RSA key of at least %d bits to sign %s.',
                self::MINIMUM_RSA_BITS,
                $algorithm->value,
            ));
        }

        try {
            return PublicJwk::rsa($details['rsa']['n'] ?? '', $details['rsa']['e'] ?? '', $algorithm);
        } catch (InvalidValue $invalid) {
            throw new SigningFailed('The signing service returned an unusable RSA public key.', previous: $invalid);
        }
    }
}
