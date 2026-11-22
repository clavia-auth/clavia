<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing;

use Clavia\Adapter\Secondary\Signing\Jose\JoseSignatureVerifier;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\TestSigningKeys;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * Verification against published keys: what the end-session endpoint relies on to tell
 * an ID token this server signed from anything else.
 */
final class JoseSignatureVerifierTest extends TestCase
{
    private InMemorySigningKeys $keys;
    private JoseSignatureVerifier $verifier;

    #[\Override]
    protected function setUp(): void
    {
        $this->keys = new InMemorySigningKeys(new FrozenClock());
        $this->keys->create(SigningAlgorithm::RS256, new DateTimeImmutable());
        $this->verifier = new JoseSignatureVerifier();
    }

    public function testATokenSignedWithAPublishedKeyGivesItsClaims(): void
    {
        $token = $this->signed(['iss' => 'https://auth.clavia.test', 'sub' => 'u-1', 'aud' => 'spa']);

        self::assertSame(
            ['iss' => 'https://auth.clavia.test', 'sub' => 'u-1', 'aud' => 'spa'],
            $this->verifier->verifiedClaims($token, $this->keys->publicKeys(), 'JWT'),
        );
    }

    public function testATokenOfAnotherTypeIsRefused(): void
    {
        // RFC 8725 §3.11: the same keys sign ID tokens, logout tokens and access tokens;
        // only `typ` tells them apart.
        $claims = ['iss' => 'https://auth.clavia.test', 'sub' => 'u-1', 'aud' => 'https://api.test/'];
        $accessToken = new CompactJws($this->keys)->sign($this->keys->activeKey(), $claims, 'at+jwt');

        self::assertNull($this->verifier->verifiedClaims($accessToken, $this->keys->publicKeys(), 'JWT'));
        self::assertSame(
            $claims,
            $this->verifier->verifiedClaims($accessToken, $this->keys->publicKeys(), 'at+jwt'),
        );
    }

    public function testATokenIsRefusedWithoutTheKeyItNames(): void
    {
        $token = $this->signed(['sub' => 'u-1']);
        // The store's first key is test key 0; key 1 is any other key.
        $otherKey = TestSigningKeys::publicJwk(1);

        self::assertNull($this->verifier->verifiedClaims($token, [$otherKey], 'JWT'));
        self::assertNull($this->verifier->verifiedClaims($token, [], 'JWT'));
    }

    public function testAnAlteredTokenIsRefused(): void
    {
        [$header, , $signature] = explode('.', $this->signed(['sub' => 'u-1']));

        $altered = $header . '.' . Base64Url::encode('{"sub":"u-2"}') . '.' . $signature;

        self::assertNull($this->verifier->verifiedClaims($altered, $this->keys->publicKeys(), 'JWT'));
    }

    public function testTheAlgorithmIsTheKeysNotTheHeaders(): void
    {
        [, $claims, $signature] = explode('.', $this->signed(['sub' => 'u-1']));
        $kid = $this->keys->activeKey()->kid;

        foreach (['none', 'HS256', 'RS512'] as $algorithm) {
            $header = Base64Url::encode((string) json_encode(['alg' => $algorithm, 'typ' => 'JWT', 'kid' => $kid]));

            self::assertNull(
                $this->verifier->verifiedClaims(
                    $header . '.' . $claims . '.' . $signature,
                    $this->keys->publicKeys(),
                    'JWT',
                ),
                $algorithm,
            );
        }
        self::assertNull(
            $this->verifier->verifiedClaims(
                Base64Url::encode('{"alg":"none","typ":"JWT"}') . '.' . $claims . '.',
                $this->keys->publicKeys(),
                'JWT',
            ),
        );
    }

    public function testWhatIsNotACompactJwsOrNotAnObjectIsRefused(): void
    {
        foreach (['', 'abc', 'a.b', 'a.b.c.d', '...'] as $garbage) {
            self::assertNull($this->verifier->verifiedClaims($garbage, $this->keys->publicKeys(), 'JWT'), $garbage);
        }

        $key = $this->keys->activeKey();
        $header = Base64Url::encode((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $key->kid]));
        $payload = Base64Url::encode('[1,2]');
        $signature = Base64Url::encode($this->keys->sign($key, $header . '.' . $payload));

        self::assertNull(
            $this->verifier->verifiedClaims(
                $header . '.' . $payload . '.' . $signature,
                $this->keys->publicKeys(),
                'JWT',
            ),
        );
    }

    /**
     * @param array<non-empty-string, mixed> $claims
     */
    private function signed(array $claims): string
    {
        return new CompactJws($this->keys)->sign($this->keys->activeKey(), $claims, 'JWT');
    }
}
