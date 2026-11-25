<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing;

use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/** The hand-built certificate (RFC 5280 §4.1), read and verified by OpenSSL, its bytes pinned. */
final class SelfSignedCertificateTest extends TestCase
{
    /** A key for this test alone: not a secret, never used anywhere else. */
    private const string TEST_KEY = <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0EF+l1ctILcTc
ooUGySkD+0WPODrsecrBxmiL1BtLTRCMIO+CFLMTPywg/iXLB+pSapfy3osVfSvO
Q9wVNWXypPhmk7f7ZJeMmr0i06FqBysWVaHWwrvacn2LVgwMomGLFSTlMHqli5/H
K8k3a0mUopVX45OPtkqH6QHbNyWk/ToC4rud/Gi0LvqwxBY6EZTZvVh+IiK2Lmf0
RCdNdA1lSilxfJhyM8DR77VLnmhyerqXCYES2QQDEbZUuDkT8Ou3JN8yQdDLrkMA
tccBXEAz9rc9uoF5TOeKZBtw4dtyikIEMoqa1/8qrGAyPOeH4S4xy9wwSxNobiTO
uUaRIFJ3AgMBAAECggEAGMK3pGJF1eMVUxG2ITzAOx/ubMdasvH8g7D452F/b1dl
kx9kUArwpRDmzJKmN8ka28J0qp0XmxjfUTnbpb72CevNjK17e0JV5KvSnltjsuTR
c/zKiHG2y087HFH0zjf2Gd4KeMm109XjXswSm2BRefLxfmh4/iYfEZlk+/QVZR6C
MTsiNE3g8DbQzvNQ9Qw1GlbPu1KxBFyFtQaAyn29r6QFd42Dntqd+NwKhTeO7xiw
HN0Edc4RQCTKKvG42IGMwJSNX8QSw9dfghoVY3lq6ICsBmZ16S30lil2/48+5kOI
GLd99hvbFGw+OMNGOVyLTZA/Y4sKmn1zNJ78rC3KoQKBgQDaXqKUQMYfMoLpm0XZ
g4LtNo9fGXmC9Z0QSLLuXA8cCiudJF39m/pwlOFIHYQkAH2oWM/o73J1ARkaRk/q
1pstl+zr1R6peZI73LQqa4sMYa58+Kdm5DBigMvS1UDm/NuuX0EE5AKc8IRD+lDf
P3w0ennMNffNm7J7Q8bP+ajbOwKBgQDTF+JtmeLZo4otU6SlPSvaPg38g5wdkDuc
B3wmZMRFLEG9oIzYhoIf2Tw8SPkVjkrQaM1/g8wq1xN5LjnWpDZYl9pEXszz9s6N
odvm91erEw+gcjoutFzIL/E4VIxurb6H7woaZ8/IQXKwBIU6tvzf+ggto+Z4qSqg
geiKf/1Z9QKBgGIw3ZAmVDAhCWa70DvPe+boeq17if0OLlLtLbAqqwyjshrWCIGK
SqGnAGnqA8oggmBZlxuZ1/CuzrfW2Aaz+1EUGI+u5Du2k7/hLQ5KD1tA7TH6qWOF
xg/09DHYfHehSbLt2BG36Ujiicb7XrQUGuiKDgx6U/QbR7VPs60/COOTAoGACatc
adzUsVd2auEb9523toWFKn301r3WnS0SmMeg3fJLCJ6kFP8EUuUmhzRohH5CGw3R
6/djkMrNT424hIZ9Hs3F57/X74zspTw20Huf/mwfGSBiXeVRIrJfgE8PJ7q5sYxX
kCIVOH0W/c0XNTtQlgnj+gM5+Wj2VOfeeQmn10kCgYEAy7e1F/FHSuWK4dyPfYzu
kvM28ATvb/QOjEGydcxoQdj2EdL/p04Odt87xulXTvHiPkA7CSnUpglUkiFL0SQ+
Ym5Sqp7LhAnthArWWoqZmJ+H/sPReisBGyQYRnNvpuhsjw9ZYPXQJwoiiCmCIUb5
VY7S/MhgSN7h5SISeDhCu3A=
-----END PRIVATE KEY-----
PEM;

    /** SHA-256 of the DER below: RSASSA-PKCS1-v1_5 is deterministic, so any change to the encoding shows. */
    private const string KNOWN_ANSWER = '18dd27855edf1978ae6a0a12e380d636ed11c4a524f516c4d514535a06ac94c0';

    public function testItIsReadVerifiedAndSaysWhatItWasGiven(): void
    {
        $pem = SelfSignedCertificate::pem(self::certificate(ServiceProviderKeyUsage::Signing));
        /** @var array{version: int, subject: array{CN: string}, issuer: array{CN: string}, serialNumberHex: string,
         *     signatureTypeSN: string, validFrom_time_t: int, validTo_time_t: int,
         *     extensions: array{keyUsage: string}}|false $parsed */
        $parsed = openssl_x509_parse($pem);

        self::assertIsArray($parsed);
        self::assertSame(2, $parsed['version'], 'v3.');
        self::assertSame('auth.clavia.test SAML SP', $parsed['subject']['CN']);
        self::assertSame('auth.clavia.test SAML SP', $parsed['issuer']['CN']);
        self::assertSame('0102030405060708', strtolower($parsed['serialNumberHex']));
        self::assertSame('RSA-SHA256', $parsed['signatureTypeSN']);
        self::assertSame(gmmktime(9, 0, 0, 3, 4, 2026), $parsed['validFrom_time_t']);
        self::assertSame(gmmktime(9, 0, 0, 3, 4, 2056), $parsed['validTo_time_t'], 'GeneralizedTime from 2050.');
        self::assertSame('Digital Signature, Certificate Sign', $parsed['extensions']['keyUsage']);
        self::assertSame(1, openssl_x509_verify($pem, self::publicKey()));
        /** @var array{extensions: array{keyUsage: string}}|false $encryption */
        $encryption = openssl_x509_parse(
            SelfSignedCertificate::pem(self::certificate(ServiceProviderKeyUsage::Encryption)),
        );
        self::assertIsArray($encryption);
        self::assertSame('Key Encipherment', $encryption['extensions']['keyUsage']);
    }

    public function testItsBytesArePinned(): void
    {
        self::assertSame(self::KNOWN_ANSWER, hash('sha256', self::certificate(ServiceProviderKeyUsage::Signing)));
    }

    public function testASignatureTheIssuerKeyDoesNotVerifyIsRefused(): void
    {
        $other = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertNotFalse($other);

        $this->expectException(\LogicException::class);
        SelfSignedCertificate::build(
            'x',
            'x',
            self::publicKey(),
            self::publicKey(),
            ServiceProviderKeyUsage::Signing,
            "\x01",
            new DateTimeImmutable('2026-03-04T09:00:00Z'),
            new DateTimeImmutable('2027-03-04T09:00:00Z'),
            static function (string $tbs) use ($other): string {
                openssl_sign($tbs, $signature, $other, OPENSSL_ALGO_SHA256);

                return $signature;
            },
        );
    }

    private static function certificate(ServiceProviderKeyUsage $usage): string
    {
        return SelfSignedCertificate::build(
            'auth.clavia.test SAML SP',
            'auth.clavia.test SAML SP',
            self::publicKey(),
            self::publicKey(),
            $usage,
            "\x01\x02\x03\x04\x05\x06\x07\x08",
            new DateTimeImmutable('2026-03-04T09:00:00Z'),
            new DateTimeImmutable('2056-03-04T09:00:00Z'),
            static function (string $tbs): string {
                openssl_sign($tbs, $signature, self::TEST_KEY, OPENSSL_ALGO_SHA256);

                return $signature;
            },
        );
    }

    private static function publicKey(): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private(self::TEST_KEY) ?: self::fail('No key.'));
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return $details['key'];
    }
}
