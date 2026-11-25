<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\X509;

use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Closure;
use DateTimeImmutable;
use LogicException;

/**
 * A minimal X.509 v3 certificate (RFC 5280 §4.1) for a service provider key, built here because
 * building one needs a signature from the key, and a KMS key gives one only through its API: the
 * `TBSCertificate` is encoded by hand and handed to a signer, as the compact JWS is
 * (docs/design/saml-connections.md §2, "Certificates"). SAML pins keys, so identity providers ignore
 * the issuer and the dates; the certificate still says the truth.
 *
 * - `sha256WithRSAEncryption` (RFC 4055 §5), the signer RSASSA-PKCS1-v1_5 over SHA-256;
 * - issuer and subject one `CN` each, UTF-8;
 * - a random positive serial (RFC 5280 §4.1.2.2: at most 20 bytes);
 * - one extension, `keyUsage` (§4.2.1.3): `digitalSignature` and `keyCertSign` for the signing
 *   key (it signs its pair's certificates), `keyEncipherment` for the encryption key.
 *
 * It is checked with OpenSSL before it is returned: parsed, and its signature verified with the
 * issuer's public key.
 */
final readonly class SelfSignedCertificate
{
    private const string SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
    private const string COMMON_NAME = '2.5.4.3';
    private const string KEY_USAGE = '2.5.29.15';

    private function __construct()
    {
    }

    /**
     * @param string                 $subject The subject's common name.
     * @param string                 $issuer The issuer's common name; the subject's if self-signed.
     * @param string                 $publicKeyPem The subject's public key (`BEGIN PUBLIC KEY`).
     * @param string                 $issuerPublicKeyPem The key the signature verifies with.
     * @param string                 $serial Unsigned big-endian, 1 to 20 bytes.
     * @param Closure(string): string $sign RSASSA-PKCS1-v1_5 over SHA-256 with the issuer's key.
     *
     * @return non-empty-string DER.
     *
     * @throws LogicException When OpenSSL does not read back what was built, or its signature fails.
     */
    public static function build(
        string $subject,
        string $issuer,
        string $publicKeyPem,
        string $issuerPublicKeyPem,
        ServiceProviderKeyUsage $usage,
        string $serial,
        DateTimeImmutable $notBefore,
        DateTimeImmutable $notAfter,
        Closure $sign,
    ): string {
        if (strlen($serial) > 20 || ltrim($serial, "\x00") === '') {
            throw new LogicException('A serial is 1 to 20 bytes, and not zero.');
        }
        if ($subject === '' || $issuer === '') {
            throw new LogicException('A certificate names its subject and its issuer.');
        }
        $algorithm = Der::sequence(Der::oid(self::SHA256_WITH_RSA), Der::null());
        [$bits, $unused] = match ($usage) {
            // digitalSignature (bit 0) and keyCertSign (bit 5): 1000 0100, two bits of padding.
            ServiceProviderKeyUsage::Signing => ["\x84", 2],
            // keyEncipherment (bit 2): 0010 0000, five bits of padding.
            ServiceProviderKeyUsage::Encryption => ["\x20", 5],
        };
        $extensions = Der::explicit(3, Der::sequence(Der::sequence(
            Der::oid(self::KEY_USAGE),
            Der::boolean(true),
            Der::octetString(Der::bitString($bits, $unused)),
        )));
        $tbs = Der::sequence(
            Der::explicit(0, Der::smallInteger(2)),
            Der::unsignedInteger($serial),
            $algorithm,
            self::name($issuer),
            Der::sequence(Der::time($notBefore), Der::time($notAfter)),
            self::name($subject),
            self::subjectPublicKeyInfo($publicKeyPem),
            $extensions,
        );
        /** @var mixed $signature */
        $signature = ($sign)($tbs);
        if (! is_string($signature) || $signature === '') {
            throw new LogicException('The signer returned no signature.');
        }
        $certificate = Der::sequence($tbs, $algorithm, Der::bitString($signature));

        $read = openssl_x509_read(self::pem($certificate));
        if ($read === false || openssl_x509_verify($read, $issuerPublicKeyPem) !== 1) {
            throw new LogicException('The certificate built does not verify with its issuer\'s key.');
        }

        return $certificate;
    }

    public static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    private static function name(string $commonName): string
    {
        return Der::sequence(Der::set(Der::sequence(Der::oid(self::COMMON_NAME), Der::utf8String($commonName))));
    }

    /** The `SubjectPublicKeyInfo` is the DER inside a `BEGIN PUBLIC KEY` PEM, as it is. */
    private static function subjectPublicKeyInfo(string $pem): string
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem) ?? '', true);

        return is_string($der) && $der !== '' ? $der : throw new LogicException('Not a public key PEM.');
    }
}
