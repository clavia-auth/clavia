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
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use PHPUnit\Framework\Attributes\Test;

/**
 * The SAML service provider keys port, every backend alike (docs/design/saml-connections.md §8): the
 * certificates are genuine and chained as designed; the current signing key signs what its
 * certificate verifies; a content key encrypted to an encryption certificate comes back, from a
 * current, next or retired key; one key never does the other's job; nothing returns key material.
 * Each backend arranges its keys its own way (made by a store, or named in a KMS).
 */
trait ServiceProviderKeysContract
{
    abstract protected function serviceProviderKeys(): ServiceProviderKeys;

    /** A current pair; with a next pair beside it; with a retired encryption key too. */
    abstract protected function arrange(bool $next = false, bool $retired = false): void;

    /** @return list<OaepDigest> The OAEP digests the current encryption key decrypts with. */
    protected function oaepDigests(): array
    {
        return OaepDigest::cases();
    }

    #[Test]
    public function aPairsCertificatesAreGenuineTheEncryptionOneSignedByTheSigningKey(): void
    {
        $this->arrange(next: true, retired: true);
        $keys = $this->serviceProviderKeys()->certificates();
        $signing = self::pem(self::key($keys->current(ServiceProviderKeyUsage::Signing)));
        $next = self::pem(self::key($keys->next(ServiceProviderKeyUsage::Signing)));

        self::assertSame(1, openssl_x509_verify($signing, self::publicKey($signing)), 'Self-signed.');
        $encryption = self::pem(self::key($keys->current(ServiceProviderKeyUsage::Encryption)));
        $nextEncryption = self::pem(self::key($keys->next(ServiceProviderKeyUsage::Encryption)));
        self::assertSame(1, openssl_x509_verify($encryption, self::publicKey($signing)), 'Signed by its pair\'s.');
        self::assertSame(1, openssl_x509_verify($nextEncryption, self::publicKey($next)));
        $parsed = openssl_x509_parse(self::pem(self::key($keys->current(ServiceProviderKeyUsage::Encryption))));
        self::assertIsArray($parsed);
        self::assertSame('Key Encipherment', $parsed['extensions']['keyUsage'] ?? null);
        self::assertCount(4, $keys->published()->keys, 'The retired key is not published.');
        self::assertStringNotContainsString('PRIVATE', serialize($keys));
    }

    #[Test]
    public function theCurrentSigningKeySignsWhatItsCertificateVerifiesAndNothingElseSigns(): void
    {
        $this->arrange(next: true);
        $keys = $this->serviceProviderKeys()->certificates();
        $current = self::key($keys->current(ServiceProviderKeyUsage::Signing));
        $data = 'SAMLRequest=abc&RelayState=xyz&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256';

        $signature = $this->serviceProviderKeys()->sign($current->kid, $data);

        $public = self::publicKey(self::pem($current));
        self::assertSame(1, openssl_verify($data, $signature, $public, OPENSSL_ALGO_SHA256));
        $refused = 0;
        foreach (
            [
                self::key($keys->current(ServiceProviderKeyUsage::Encryption))->kid,
                self::key($keys->next(ServiceProviderKeyUsage::Signing))->kid,
                'unknown',
            ] as $kid
        ) {
            try {
                $this->serviceProviderKeys()->sign($kid, $data);
                self::fail($kid . ' signed.');
            } catch (SigningFailed) {
                ++$refused;
            }
        }
        self::assertSame(3, $refused, 'The encryption key, the next signing key, an unknown one.');
    }

    #[Test]
    public function aContentKeyEncryptedToTheCertificateDecrypts(): void
    {
        $this->arrange();
        $key = self::key($this->serviceProviderKeys()->certificates()->current(ServiceProviderKeyUsage::Encryption));
        $contentKey = random_bytes(32);

        foreach ($this->oaepDigests() as $digest) {
            self::assertSame($contentKey, $this->serviceProviderKeys()->decryptKey(
                $key->kid,
                self::encrypted($contentKey, $key, $digest),
                $digest,
            ), $digest->value);
        }
    }

    #[Test]
    public function nextAndRetiredEncryptionKeysDecryptToo(): void
    {
        $this->arrange(next: true, retired: true);
        $keys = $this->serviceProviderKeys()->certificates();
        $retired = array_values(array_filter(
            $keys->keys,
            static fn (ServiceProviderKey $k): bool => $k->status === ServiceProviderKeyStatus::Retired,
        ));
        self::assertCount(1, $retired);

        foreach ([self::key($keys->next(ServiceProviderKeyUsage::Encryption)), $retired[0]] as $key) {
            $digest = $this->oaepDigests()[0];
            self::assertSame(
                'content-key',
                $this->serviceProviderKeys()->decryptKey(
                    $key->kid,
                    self::encrypted('content-key', $key, $digest),
                    $digest,
                ),
                $key->status->value,
            );
        }
    }

    #[Test]
    public function aSigningKeyNeverDecryptsAndABadCiphertextIsOneRefusal(): void
    {
        $this->arrange();
        $keys = $this->serviceProviderKeys()->certificates();
        $signing = self::key($keys->current(ServiceProviderKeyUsage::Signing));
        $encryption = self::key($keys->current(ServiceProviderKeyUsage::Encryption));
        $digest = $this->oaepDigests()[0];

        $attempts = [
            [$signing->kid, self::encrypted('k', $signing, $digest)],
            [$encryption->kid, str_repeat('x', 256)],
            ['unknown', self::encrypted('k', $encryption, $digest)],
        ];
        foreach ($attempts as [$kid, $ciphertext]) {
            try {
                $this->serviceProviderKeys()->decryptKey($kid, $ciphertext, $digest);
                self::fail('It decrypted.');
            } catch (DecryptionFailed $refusal) {
                self::assertSame('The content key does not decrypt.', $refusal->getMessage(), 'One answer.');
            }
        }
    }

    private static function key(?ServiceProviderKey $key): ServiceProviderKey
    {
        self::assertNotNull($key);

        return $key;
    }

    private static function encrypted(string $plaintext, ServiceProviderKey $key, OaepDigest $digest): string
    {
        self::assertTrue(openssl_public_encrypt(
            $plaintext,
            $encrypted,
            self::publicKey(self::pem($key)),
            OPENSSL_PKCS1_OAEP_PADDING,
            $digest->value,
        ));

        return $encrypted;
    }

    private static function pem(ServiceProviderKey $key): string
    {
        $der = base64_decode($key->certificate, true);
        self::assertIsString($der);

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
