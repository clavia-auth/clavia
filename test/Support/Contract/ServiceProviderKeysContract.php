<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * The SAML service provider keys, the double and every backend alike (docs/design/saml-connections.md
 * §8): a pair's certificates are genuine and chained as designed; the current signing key signs what
 * its certificate verifies; a content key encrypted to the encryption certificate comes back, also
 * from a next or a retired key; one key never does the other's job; nothing returns key material.
 */
trait ServiceProviderKeysContract
{
    abstract protected function serviceProviderKeyStore(): ServiceProviderKeyStore;

    abstract protected function serviceProviderKeys(): ServiceProviderKeys;

    #[Test]
    public function aPairsCertificatesAreGenuineTheEncryptionOneSignedByTheSigningKey(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $signing = self::pem($pair['signing']);
        $encryption = self::pem($pair['encryption']);

        self::assertSame(1, openssl_x509_verify($signing, self::publicKey($signing)), 'Self-signed.');
        self::assertSame(1, openssl_x509_verify($encryption, self::publicKey($signing)), 'Signed by the signing key.');
        $parsed = openssl_x509_parse($encryption);
        self::assertIsArray($parsed);
        self::assertSame('Key Encipherment', $parsed['extensions']['keyUsage'] ?? null);
        self::assertSame(
            $pair['signing']->kid,
            $this->serviceProviderKeys()->certificates()->current(ServiceProviderKeyUsage::Signing)?->kid,
        );
        self::assertSame(
            $pair['encryption']->kid,
            $this->serviceProviderKeys()->certificates()->current(ServiceProviderKeyUsage::Encryption)?->kid,
        );
        self::assertStringNotContainsString('PRIVATE', serialize($this->serviceProviderKeys()->certificates()));
        self::assertStringNotContainsString('PRIVATE', serialize($pair));
    }

    #[Test]
    public function theCurrentSigningKeySignsWhatItsCertificateVerifies(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $data = 'SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';

        $signature = $this->serviceProviderKeys()->sign($pair['signing']->kid, $data);

        $public = self::publicKey(self::pem($pair['signing']));
        self::assertSame(1, openssl_verify($data, $signature, $public, OPENSSL_ALGO_SHA256));
        $this->expectException(SigningFailed::class);
        $this->serviceProviderKeys()->sign($pair['encryption']->kid, $data);
    }

    #[Test]
    public function aNextSigningKeyDoesNotSignYet(): void
    {
        $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $next = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Next, self::moment());

        $this->expectException(SigningFailed::class);
        $this->serviceProviderKeys()->sign($next['signing']->kid, 'data');
    }

    #[Test]
    public function aContentKeyEncryptedToTheCertificateDecryptsWithEitherOaepDigest(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $public = self::publicKey(self::pem($pair['encryption']));
        $contentKey = random_bytes(32);

        foreach (OaepDigest::cases() as $digest) {
            self::assertTrue(
                openssl_public_encrypt($contentKey, $encrypted, $public, OPENSSL_PKCS1_OAEP_PADDING, $digest->value),
            );
            self::assertSame(
                $contentKey,
                $this->serviceProviderKeys()->decryptKey($pair['encryption']->kid, $encrypted, $digest),
            );
        }
    }

    #[Test]
    public function aSigningKeyNeverDecryptsAndABadCiphertextIsOneRefusal(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $signingPublic = self::publicKey(self::pem($pair['signing']));
        openssl_public_encrypt('k', $encrypted, $signingPublic, OPENSSL_PKCS1_OAEP_PADDING);

        $attempts = [
            [$pair['signing']->kid, $encrypted],
            [$pair['encryption']->kid, 'garbage'],
            ['unknown', $encrypted],
        ];
        foreach ($attempts as [$kid, $ciphertext]) {
            try {
                $this->serviceProviderKeys()->decryptKey($kid, $ciphertext, OaepDigest::Sha1);
                self::fail('It decrypted.');
            } catch (DecryptionFailed $refusal) {
                self::assertSame('The content key does not decrypt.', $refusal->getMessage(), 'One answer.');
            }
        }
    }

    #[Test]
    public function aRetiredEncryptionKeyStillDecryptsUntilDeleted(): void
    {
        $pair = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $store = $this->serviceProviderKeyStore();
        $store->save($pair['signing']->retired(self::moment()));
        $store->save($pair['encryption']->retired(self::moment()));
        $public = self::publicKey(self::pem($pair['encryption']));
        openssl_public_encrypt('content-key', $encrypted, $public, OPENSSL_PKCS1_OAEP_PADDING);

        self::assertSame(
            'content-key',
            $this->serviceProviderKeys()->decryptKey($pair['encryption']->kid, $encrypted, OaepDigest::Sha1),
        );
        self::assertSame([], $this->serviceProviderKeys()->certificates()->published()->keys, 'No longer published.');
        self::assertCount(2, $store->all()->keys);

        $store->delete($pair['encryption']->kid);
        $this->expectException(DecryptionFailed::class);
        $this->serviceProviderKeys()->decryptKey($pair['encryption']->kid, $encrypted, OaepDigest::Sha1);
    }

    #[Test]
    public function aNextPairIsPromotedAndTheCurrentOneRetired(): void
    {
        $current = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Current, self::moment());
        $next = $this->serviceProviderKeyStore()->createPair(ServiceProviderKeyStatus::Next, self::moment());
        $later = self::moment()->modify('+14 days');
        $store = $this->serviceProviderKeyStore();

        $store->save($current['signing']->retired($later));
        $store->save($current['encryption']->retired($later));
        $store->save($next['signing']->promoted($later));
        $store->save($next['encryption']->promoted($later));

        $keys = $this->serviceProviderKeys()->certificates();
        self::assertSame($next['signing']->kid, $keys->current(ServiceProviderKeyUsage::Signing)?->kid);
        self::assertEquals($later, $keys->current(ServiceProviderKeyUsage::Signing)?->promotedAt);
        self::assertSame(ServiceProviderKeyStatus::Retired, $keys->byKid($current['signing']->kid)?->status);
        self::assertNotSame('', $this->serviceProviderKeys()->sign($next['signing']->kid, 'data'));
    }

    private static function moment(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-03-04T09:00:00.000000Z');
    }

    private static function pem(ServiceProviderKey $key): string
    {
        $der = base64_decode($key->certificate, true);
        self::assertIsString($der);
        self::assertNotSame('', $der);

        return SelfSignedCertificate::pem($der);
    }

    private static function publicKey(string $pem): string
    {
        $key = openssl_pkey_get_public($pem);
        self::assertNotFalse($key);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return $details['key'];
    }
}
