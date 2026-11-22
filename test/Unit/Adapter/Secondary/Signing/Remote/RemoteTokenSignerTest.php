<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteTokenSigner;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Fake\InMemoryPublicKeyCache;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\LocalSigningKey;
use ClaviaTest\Support\TestSigningKeys;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\TestCase;

final class RemoteTokenSignerTest extends TestCase
{
    private InMemoryPublicKeyCache $cache;

    #[\Override]
    protected function setUp(): void
    {
        $this->cache = new InMemoryPublicKeyCache();
        LocalSigningKey::$publicKeyReads = [];
    }

    public function testTheActiveKeyIsNamedByTheThumbprintOfWhatTheProviderPublishes(): void
    {
        $active = $this->signer()->activeKey();

        self::assertSame(new LocalHsm(1)->kid(), $active->kid);
        self::assertSame(SigningAlgorithm::RS256, $active->algorithm);
    }

    public function testWhatItSignsIsRs256OverTheExactInputAndVerifiesAgainstTheActiveKey(): void
    {
        $signer = $this->signer();

        $signature = $signer->sign($signer->activeKey(), 'eyJhbGciOiJSUzI1NiJ9.e30');

        self::assertSame(new LocalHsm(1)->signDigest(hash('sha256', 'eyJhbGciOiJSUzI1NiJ9.e30', true)), $signature);
        self::assertTrue(new RS256()->verify(
            new JWK(TestSigningKeys::publicJwk(1)->toArray()),
            'eyJhbGciOiJSUzI1NiJ9.e30',
            $signature,
        ));
    }

    public function testTheActiveKeyIsPublishedFirstThenEachRetiredOne(): void
    {
        $signer = $this->signer(new LocalSigningKey('local:2'), new LocalSigningKey('local:3'));

        self::assertSame(
            [new LocalHsm(1)->kid(), new LocalHsm(2)->kid(), new LocalHsm(3)->kid()],
            array_map(static fn (PublicJwk $jwk): string => $jwk->kid, $signer->publicKeys()),
        );
    }

    public function testARetiredKeySignsNothing(): void
    {
        $signer = $this->signer(new LocalSigningKey('local:2'));

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('is not the active key');

        $_ = $signer->sign(new SigningKeyReference(new LocalHsm(2)->kid(), SigningAlgorithm::RS256), 'header.payload');
    }

    public function testEachPublicKeyIsReadFromItsProviderOnceAndThenFromTheCache(): void
    {
        $signer = $this->signer(new LocalSigningKey('local:2'));
        $_ = $signer->activeKey();
        $_ = $signer->publicKeys();
        $_ = $signer->sign($signer->activeKey(), 'header.payload');

        // Another process: an empty memory, the shared cache.
        $_ = $this->signer(new LocalSigningKey('local:2'))->publicKeys();

        self::assertSame(['local:1' => 1, 'local:2' => 1], LocalSigningKey::$publicKeyReads);
    }

    public function testASignatureThatDoesNotVerifyNeverLeaves(): void
    {
        // A provider signing with another key than the one it publishes — the symptom of a
        // message signed as a digest, or a key swapped behind its reference.
        $impostor = new readonly class implements RemoteSigningKey {
            #[\Override]
            public function reference(): string
            {
                return 'impostor';
            }

            #[\Override]
            public function sign(string $digest, SigningAlgorithm $algorithm): string
            {
                $signature = new LocalHsm(4)->signDigest($digest);
                assert($signature !== '');

                return $signature;
            }

            #[\Override]
            public function publicKey(SigningAlgorithm $algorithm): PublicJwk
            {
                return TestSigningKeys::publicJwk(1);
            }
        };
        $signer = new RemoteTokenSigner($impostor, [], SigningAlgorithm::RS256, $this->cache);

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('does not verify against its public key');

        $_ = $signer->sign($signer->activeKey(), 'header.payload');
    }

    private function signer(RemoteSigningKey ...$retired): RemoteTokenSigner
    {
        return new RemoteTokenSigner(
            new LocalSigningKey('local:1'),
            array_values($retired),
            SigningAlgorithm::RS256,
            $this->cache,
        );
    }
}
