<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Clavia\Adapter\Secondary\Signing\X509\Der;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\InvalidValue;

/**
 * An RSA public key as the certificates need it (`BEGIN PUBLIC KEY`, a `SubjectPublicKeyInfo`,
 * RFC 5280 §4.1.2.7 with RFC 3279 §2.3.1's `rsaEncryption`), from what each provider hands back, and
 * its RFC 7638 thumbprint, the kid every service provider key is named by.
 */
final readonly class RsaPublicKey
{
    private const string RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

    private function __construct()
    {
    }

    /**
     * @return non-empty-string
     *
     * @throws InvalidValue When the numbers are empty.
     */
    public static function pem(string $modulus, string $exponent): string
    {
        if (ltrim($modulus, "\x00") === '' || ltrim($exponent, "\x00") === '') {
            throw new InvalidValue('An RSA public key has a modulus and an exponent.');
        }
        $spki = Der::sequence(
            Der::sequence(Der::oid(self::RSA_ENCRYPTION), Der::null()),
            Der::bitString(Der::sequence(Der::unsignedInteger($modulus), Der::unsignedInteger($exponent))),
        );

        return self::pemFromDer($spki);
    }

    /** @return non-empty-string */
    public static function fromJwk(PublicJwk $jwk): string
    {
        /** @var array{n: string, e: string} $members */
        $members = $jwk->toArray();

        return self::pem(Base64Url::decode($members['n']), Base64Url::decode($members['e']));
    }

    /** @return non-empty-string */
    public static function pemFromDer(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    /**
     * The RFC 7638 thumbprint of an RSA public key PEM.
     *
     * @return non-empty-string
     *
     * @throws InvalidValue When it is not an RSA key.
     */
    public static function kid(string $pem): string
    {
        $key = openssl_pkey_get_public($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        /** @var array{rsa?: array{n?: string, e?: string}}|false $details */
        $rsa = $details === false ? [] : ($details['rsa'] ?? []);
        if (! isset($rsa['n'], $rsa['e'])) {
            throw new InvalidValue('Not an RSA public key.');
        }

        return PublicJwk::rsa($rsa['n'], $rsa['e'], SigningAlgorithm::RS256)->kid;
    }
}
