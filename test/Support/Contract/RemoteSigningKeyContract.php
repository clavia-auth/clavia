<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Adapter\Secondary\Signing\Jose\JoseSignatureVerifier;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteTokenSigner;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Fake\InMemoryPublicKeyCache;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\TestSigningKeys;
use PHPUnit\Framework\Attributes\Test;

/**
 * The one property every remote key has, checked the same way for each provider: a token
 * signed through it verifies against the key set it publishes — what a relying party
 * ultimately checks.
 */
trait RemoteSigningKeyContract
{
    /** The key under test, served by a fake of its provider holding {@see hsm()}. */
    abstract protected function key(): RemoteSigningKey;

    abstract protected function hsm(): LocalHsm;

    #[Test]
    public function aTokenItSignsVerifiesAgainstThePublishedKeys(): void
    {
        $signer = new RemoteTokenSigner($this->key(), [], SigningAlgorithm::RS256, new InMemoryPublicKeyCache());
        $active = $signer->activeKey();

        $claims = ['iss' => 'https://issuer.test', 'sub' => 'conformance'];
        $token = new CompactJws($signer)->sign($active, $claims, 'JWT');

        self::assertSame(
            $claims,
            new JoseSignatureVerifier()->verifiedClaims($token, $signer->publicKeys(), 'JWT'),
        );
    }

    #[Test]
    public function itsKidIsTheThumbprintOfItsKeyAndNamesNoAccount(): void
    {
        $published = $this->key()->publicKey(SigningAlgorithm::RS256);

        self::assertEquals(TestSigningKeys::publicJwk(0), $published);
        self::assertSame($this->hsm()->kid(), $published->kid);
        // 43 base64url characters of SHA-256: nothing of the ARN, project or vault it lives in.
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $published->kid);
    }
}
