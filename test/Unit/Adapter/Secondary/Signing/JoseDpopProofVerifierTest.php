<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing;

use Clavia\Adapter\Secondary\Signing\Jose\JoseDpopProofVerifier;
use Clavia\Domain\OAuth2\Dpop\DpopAlgorithm;
use ClaviaTest\Support\DpopClient;
use Fig\Http\Message\RequestMethodInterface;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The cryptography of a DPoP proof (RFC 9449 §4.3 steps 2–8), with real keys.
 */
final class JoseDpopProofVerifierTest extends TestCase
{
    private const string URL = 'https://auth.clavia.test/oauth2/token';

    /** @return iterable<string, array{DpopClient}> */
    public static function clients(): iterable
    {
        yield 'ES256' => [DpopClient::es256()];
        yield 'EdDSA' => [DpopClient::edDsa()];
        yield 'RS256' => [DpopClient::rs256()];
    }

    #[DataProvider('clients')]
    public function testAProofOfEachAlgorithmVerifiesAndSaysWhatItIsFor(DpopClient $client): void
    {
        $proof = new JoseDpopProofVerifier()->verify(
            $client->proof(RequestMethodInterface::METHOD_POST, self::URL, 'n-1', 'the-token'),
        );

        self::assertNotNull($proof);
        self::assertSame($client->thumbprint(), $proof->thumbprint->value);
        self::assertSame(DpopAlgorithm::from($client->algorithm), $proof->algorithm);
        self::assertSame(RequestMethodInterface::METHOD_POST, $proof->method);
        self::assertSame(self::URL, $proof->url);
        self::assertSame('n-1', $proof->nonce);
        self::assertNotNull($proof->accessTokenHash);
    }

    public function testTheThumbprintIsRfc7638s(): void
    {
        // RFC 7638 §3.1's example key and its thumbprint.
        $jwk = new JWK([
            'kty' => 'RSA',
            'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJE'
                . 'CPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q'
                . 'vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6'
                . 'WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
            'e' => 'AQAB',
        ]);

        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $jwk->thumbprint('sha256'));
    }

    /** @return iterable<string, array{string}> */
    public static function forgeries(): iterable
    {
        $es = DpopClient::es256();
        [$header, $payload, $signature] = explode('.', $es->proof(RequestMethodInterface::METHOD_POST, self::URL));

        yield 'not a JWS' => ['not.a.proof'];
        yield 'another typ' => [$es->proof(RequestMethodInterface::METHOD_POST, self::URL, headers: ['typ' => 'JWT'])];
        $rsHeader = rtrim(strtr(base64_encode((string) json_encode(
            ['typ' => 'dpop+jwt', 'alg' => 'RS256', 'jwk' => $es->key->toPublic()->all()],
        )), '+/', '-_'), '=');
        yield 'an algorithm the key does not sign with' => [$rsHeader . '.' . $payload . '.' . $signature];
        yield 'a private member in the jwk' => [
            $es->proof(RequestMethodInterface::METHOD_POST, self::URL, headers: ['jwk' => $es->key->all()]),
        ];
        $changed = self::b64('{"jti":"x","htm":"POST","htu":"u","iat":1}');
        yield 'a changed payload' => [$header . '.' . $changed . '.' . $signature];
        yield 'no signature' => [$header . '.' . $payload . '.'];
        yield 'a missing jti' => [$es->proof(RequestMethodInterface::METHOD_POST, self::URL, claims: ['jti' => null])];
        yield 'an iat that is not a number' => [
            $es->proof(RequestMethodInterface::METHOD_POST, self::URL, claims: ['iat' => 'yesterday']),
        ];
        yield 'an RSA key under 2048 bits' => [
            DpopClient::rs256(1024)->proof(RequestMethodInterface::METHOD_POST, self::URL),
        ];
        yield 'a MAC' => [self::mac()];
        yield 'PS256, which is not offered' => [self::ps256()];
    }

    #[DataProvider('forgeries')]
    public function testAnythingElseIsNoProof(string $proof): void
    {
        self::assertNull(new JoseDpopProofVerifier()->verify($proof));
    }

    /**
     * A PS256 header over an RS256 signature: refused for its algorithm before any RSA-PSS
     * arithmetic, which is what keeps forged proofs cheap to refuse.
     */
    private static function ps256(): string
    {
        $client = DpopClient::rs256();
        [, $payload, $signature] = explode('.', $client->proof(RequestMethodInterface::METHOD_POST, self::URL));
        $header = rtrim(strtr(base64_encode((string) json_encode(
            ['typ' => 'dpop+jwt', 'alg' => 'PS256', 'jwk' => $client->key->toPublic()->all()],
        )), '+/', '-_'), '=');

        return $header . '.' . $payload . '.' . $signature;
    }

    /** HS256 with a symmetric key: a MAC is no proof of possession of anything. */
    private static function mac(): string
    {
        $header = self::b64('{"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"oct","k":"c2VjcmV0"}}');
        $payload = self::b64('{"jti":"x","htm":"POST","htu":"' . self::URL . '","iat":' . time() . '}');
        $signature = self::b64(hash_hmac('sha256', $header . '.' . $payload, 'secret', true));

        return $header . '.' . $payload . '.' . $signature;
    }

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
