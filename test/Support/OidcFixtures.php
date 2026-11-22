<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * OpenID Connect flows for acceptance tests, and ID tokens checked the way a relying
 * party checks them: against the JWKS fetched over HTTP, never by reaching into storage.
 *
 * For a test case that also uses {@see OAuth2Fixtures}.
 */
trait OidcFixtures
{
    /**
     * Authorize, then redeem the code: the token response, decoded.
     *
     * @param array<string, string|null> $authorizeOverrides
     *
     * @return array<array-key, mixed>
     */
    protected function completeFlow(string $scope = 'openid email', array $authorizeOverrides = []): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => $scope] + $authorizeOverrides);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());

        return self::json($response);
    }

    /**
     * The published JWK Set, fetched as a relying party would.
     */
    protected function publishedKeySet(): JWKSet
    {
        /** @var array{keys: list<array<string, string>>} $document */
        $document = self::json($this->get('/oidc/jwks.json'));

        return JWKSet::createFromKeyData($document);
    }

    /**
     * Verify an ID token's RS256 signature against the published keys, then return its
     * protected header and claims. Fails the test when no published key verifies it.
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    protected function verifiedIdToken(mixed $idToken): array
    {
        self::assertIsString($idToken, 'no ID token in the response');

        return $this->verifiedJwt($idToken);
    }

    /**
     * Verify any JWT this server signed — an ID token, a JWT access token — the way its
     * recipient does: RS256 against the published JWKS. Returns its protected header and
     * claims; fails the test when no published key verifies it.
     *
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}
     */
    protected function verifiedJwt(string $jwt): array
    {
        $jws = new CompactSerializer()->unserialize($jwt);
        $verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
        self::assertTrue(
            $verifier->verifyWithKeySet($jws, $this->publishedKeySet(), 0),
            'the JWT does not verify against the published JWKS',
        );

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) $jws->getPayload(), true, flags: JSON_THROW_ON_ERROR);

        return ['header' => $jws->getSignature(0)->getProtectedHeader(), 'claims' => $claims];
    }
}
