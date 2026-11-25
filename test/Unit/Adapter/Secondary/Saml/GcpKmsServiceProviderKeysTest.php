<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Saml\Remote\GcpKmsDecryptionKey;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteDecryptionKey;
use Clavia\Adapter\Secondary\Signing\Remote\Gcp\GcpKmsKey;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\DecryptionFailed;
use Clavia\Application\Port\Saml\OaepDigest;
use ClaviaTest\Support\Contract\ServiceProviderKeysContract;
use ClaviaTest\Support\Fake\FakeCloudKms;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\StaticAccessTokens;
use ClaviaTest\Support\RemoteServiceProviderKeysFixture;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The SAML keys in Google Cloud KMS, over its mocked transport: an ASYMMETRIC_SIGN and an
 * ASYMMETRIC_DECRYPT key version, the latter's OAEP digest its own (SHA-256 here).
 */
final class GcpKmsServiceProviderKeysTest extends TestCase
{
    use ServiceProviderKeysContract;
    use RemoteServiceProviderKeysFixture;

    /** @var array<int, FakeCloudKms> */
    private array $kms = [];

    /**
     * Replaces the contract's: a Cloud KMS key version has one OAEP digest.
     *
     * @return list<OaepDigest>
     */
    protected function oaepDigests(): array
    {
        return [OaepDigest::Sha256];
    }

    #[\Override]
    protected function remoteSigningKey(int $index): RemoteSigningKey
    {
        $this->kms($index, 'RSA_SIGN_PKCS1_2048_SHA256');

        return new GcpKmsKey($this->api(), new StaticAccessTokens('google-token'), self::version($index));
    }

    #[\Override]
    protected function remoteDecryptionKey(int $index): RemoteDecryptionKey
    {
        $this->kms($index, 'RSA_DECRYPT_OAEP_2048_SHA256');

        return new GcpKmsDecryptionKey($this->api(), new StaticAccessTokens('google-token'), self::version($index));
    }

    public function testAContentKeyWrappedWithAnotherOaepDigestThanTheKeyVersionsIsRefused(): void
    {
        $this->arrange();
        $key = $this->serviceProviderKeys()->certificates()->current(ServiceProviderKeyUsage::Encryption)
            ?? self::fail('No encryption key.');

        $this->expectException(DecryptionFailed::class);
        $this->serviceProviderKeys()->decryptKey($key->kid, str_repeat('x', 256), OaepDigest::Sha1);
    }

    private function kms(int $index, string $algorithm): void
    {
        if (! isset($this->kms[$index])) {
            $this->kms[$index] = new FakeCloudKms(self::version($index), new LocalHsm($index));
            $this->kms[$index]->algorithm = $algorithm;
        }
    }

    private function api(): JsonApi
    {
        $route = function (RequestInterface $request): ResponseInterface {
            $path = (string) $request->getUri();
            foreach ($this->kms as $kms) {
                $prefix = GcpKmsKey::API . $kms->keyVersion;
                if (str_starts_with($path, $prefix . ':') || str_starts_with($path, $prefix . '/')) {
                    return $kms($request);
                }
            }

            return new JsonResponse(
                ['error' => ['code' => StatusCodeInterface::STATUS_NOT_FOUND, 'message' => 'Not found.']],
                StatusCodeInterface::STATUS_NOT_FOUND,
            );
        };

        return new JsonApi(new FakeHttpClient($route), new RequestFactory(), new StreamFactory(), 'Google Cloud KMS');
    }

    private static function version(int $index): string
    {
        return 'projects/p/locations/europe-west1/keyRings/clavia/cryptoKeys/saml-' . $index . '/cryptoKeyVersions/1';
    }
}
