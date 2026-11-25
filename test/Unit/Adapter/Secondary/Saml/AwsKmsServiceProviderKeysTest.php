<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Aws\CommandInterface;
use Clavia\Adapter\Secondary\Saml\Remote\AwsKmsDecryptionKey;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteDecryptionKey;
use Clavia\Adapter\Secondary\Signing\Remote\Aws\AwsKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use ClaviaTest\Support\Contract\ServiceProviderKeysContract;
use ClaviaTest\Support\Fake\FakeKms;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\RemoteServiceProviderKeysFixture;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use PHPUnit\Framework\TestCase;

/** The SAML keys in AWS KMS, over its mocked transport: a SIGN_VERIFY and an ENCRYPT_DECRYPT key. */
final class AwsKmsServiceProviderKeysTest extends TestCase
{
    use ServiceProviderKeysContract;
    use RemoteServiceProviderKeysFixture;

    /** @var array<int, FakeKms> */
    private array $kms = [];

    #[\Override]
    protected function remoteSigningKey(int $index): RemoteSigningKey
    {
        return new AwsKmsKey($this->kms($index, 'SIGN_VERIFY')->client(), self::arn($index));
    }

    #[\Override]
    protected function remoteDecryptionKey(int $index): RemoteDecryptionKey
    {
        return new AwsKmsDecryptionKey($this->kms($index, 'ENCRYPT_DECRYPT')->client(), self::arn($index));
    }

    public function testKmsIsHandedTheContentKeyWithItsOwnNameForOaep(): void
    {
        $this->arrange();
        $key = $this->serviceProviderKeys()->certificates()->current(ServiceProviderKeyUsage::Encryption)
            ?? self::fail('No encryption key.');
        $public = self::publicOf($key->certificate);
        self::assertTrue(openssl_public_encrypt('k', $encrypted, $public, OPENSSL_PKCS1_OAEP_PADDING, 'sha256'));

        self::assertSame('k', $this->serviceProviderKeys()->decryptKey($key->kid, $encrypted, OaepDigest::Sha256));
        $decrypt = array_values(array_filter(
            $this->kms[1]->commands,
            static fn (CommandInterface $command): bool => $command->getName() === 'Decrypt',
        ));
        self::assertSame('RSAES_OAEP_SHA_256', $decrypt[0]['EncryptionAlgorithm']);
        self::assertSame(self::arn(1), $decrypt[0]['KeyId']);
    }

    public function testAKeyThatDoesNotDecryptIsRefusedWhenItsCertificateIsMade(): void
    {
        $this->kms[1] = new FakeKms(new LocalHsm(1));
        $this->kms[1]->keyUsage = 'SIGN_VERIFY';
        $this->arrange();

        $this->expectException(DecryptionFailed::class);
        $this->serviceProviderKeys()->certificates();
    }

    public function testCertificatesAreMadeOnceThenServedWithoutKms(): void
    {
        $this->arrange();
        $this->serviceProviderKeys()->certificates();
        $calls = $this->calls();

        $this->serviceProviderKeys()->certificates();

        self::assertSame($calls, $this->calls());
    }

    private function calls(): int
    {
        return array_sum(array_map(static fn (FakeKms $kms): int => count($kms->commands), $this->kms));
    }

    private function kms(int $index, string $usage): FakeKms
    {
        if (! isset($this->kms[$index])) {
            $this->kms[$index] = new FakeKms(new LocalHsm($index));
            $this->kms[$index]->keyUsage = $usage;
        }

        return $this->kms[$index];
    }

    private static function arn(int $index): string
    {
        return sprintf('arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-12345678900%d', $index);
    }

    private static function publicOf(string $certificate): string
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public(
            "-----BEGIN CERTIFICATE-----\n" . chunk_split($certificate, 64, "\n") . "-----END CERTIFICATE-----\n",
        ) ?: self::fail('No key.'));
        self::assertIsArray($details);
        self::assertIsString($details['key']);

        return $details['key'];
    }
}
