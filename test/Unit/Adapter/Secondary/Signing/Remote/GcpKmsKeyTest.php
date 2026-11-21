<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GcpKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Contract\RemoteSigningKeyContract;
use ClaviaTest\Support\Fake\FakeCloudKms;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\StaticAccessTokens;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;

final class GcpKmsKeyTest extends TestCase
{
    use RemoteSigningKeyContract;

    private const string VERSION = 'projects/secret-project/locations/europe-west1/keyRings/clavia/cryptoKeys/signing/'
        . 'cryptoKeyVersions/3';

    private FakeCloudKms $kms;

    private FakeHttpClient $http;

    #[\Override]
    protected function setUp(): void
    {
        $this->kms = new FakeCloudKms(self::VERSION);
        $this->http = new FakeHttpClient($this->kms);
    }

    #[\Override]
    protected function key(): RemoteSigningKey
    {
        return self::keyFor($this->http, self::VERSION);
    }

    #[\Override]
    protected function hsm(): LocalHsm
    {
        return new LocalHsm();
    }

    public function testCloudKmsIsHandedTheDigestWithItsChecksumAndABearerToken(): void
    {
        $digest = hash('sha256', 'header.payload', true);

        $signature = $this->key()->sign($digest, SigningAlgorithm::RS256);

        self::assertSame(new LocalHsm()->signDigest($digest), $signature);
        $request = $this->http->requests[0] ?? null;
        self::assertNotNull($request);
        self::assertSame(GcpKmsKey::API . self::VERSION . ':asymmetricSign', (string) $request->getUri());
        self::assertSame('Bearer google-token', $request->getHeaderLine('Authorization'));
        self::assertSame(
            [
                'digest' => ['sha256' => base64_encode($digest)],
                'digestCrc32c' => (string) hexdec(hash('crc32c', $digest)),
            ],
            json_decode((string) $request->getBody(), true),
        );
    }

    public function testAKeyRatherThanAKeyVersionIsRefused(): void
    {
        $this->expectException(InvalidKeyReference::class);
        $this->expectExceptionMessage('cryptoKeyVersions/N');

        self::keyFor($this->http, 'projects/p/locations/l/keyRings/r/cryptoKeys/signing');
    }

    public function testADigestCloudKmsDidNotConfirmIsNotUsed(): void
    {
        $this->kms->confirmDigest = false;

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('did not confirm the digest');

        $_ = $this->key()->sign(hash('sha256', 'x', true), SigningAlgorithm::RS256);
    }

    public function testASignatureThatDoesNotMatchItsChecksumIsNotUsed(): void
    {
        $this->kms->corruptSignature = true;

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('does not match its checksum');

        $_ = $this->key()->sign(hash('sha256', 'x', true), SigningAlgorithm::RS256);
    }

    public function testEveryRsaPkcs1Sha256KeySizeSignsRs256AndNothingElseDoes(): void
    {
        foreach (['RSA_SIGN_PKCS1_2048_SHA256', 'RSA_SIGN_PKCS1_3072_SHA256', 'RSA_SIGN_PKCS1_4096_SHA256'] as $name) {
            self::assertTrue(GcpKmsKey::signsWith($name, SigningAlgorithm::RS256), $name);
        }
        foreach (['RSA_SIGN_PSS_2048_SHA256', 'RSA_SIGN_PKCS1_4096_SHA512', 'EC_SIGN_P256_SHA256'] as $name) {
            self::assertFalse(GcpKmsKey::signsWith($name, SigningAlgorithm::RS256), $name);
        }

        $this->kms->algorithm = 'EC_SIGN_P256_SHA256';
        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('does not sign with RS256');

        $this->key()->publicKey(SigningAlgorithm::RS256);
    }

    public function testARefusalRepeatsWhatCloudKmsSaid(): void
    {
        $key = new GcpKmsKey(self::api($this->http), new StaticAccessTokens('expired-token'), self::VERSION);

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('Google Cloud KMS refused the request (HTTP 401): Request had invalid');

        $key->publicKey(SigningAlgorithm::RS256);
    }

    private static function keyFor(FakeHttpClient $http, string $reference): GcpKmsKey
    {
        return new GcpKmsKey(self::api($http), new StaticAccessTokens('google-token'), $reference);
    }

    private static function api(FakeHttpClient $http): JsonApi
    {
        return new JsonApi($http, new RequestFactory(), new StreamFactory(), 'Google Cloud KMS');
    }
}
