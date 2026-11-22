<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Configuration\Settings;
use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestStorage;
use Psr\Http\Message\ResponseInterface;

/**
 * JWT access tokens (RFC 9068), chosen per API.
 *
 * Checked the way an API checks them: the signature against the JWKS fetched over HTTP,
 * then the header and the claims. And checked the way this server treats them: recorded
 * like any other token, so introspection and revocation still answer here.
 */
final class JwtAccessTokenTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use OidcFixtures;

    public function testAnApiIsIssuedOpaqueTokensByDefault(): void
    {
        $this->machineApi();

        $token = self::issued($this->requestMachineToken());

        // 43 base64url characters: no header, no claims, nothing to read.
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $token['access_token']);
    }

    public function testAMachineTokenIsAJwtAccessToken(): void
    {
        $this->jwtApi($this->machineApi());

        $response = $this->requestMachineToken();
        $token = self::issued($response);
        $jwt = $this->verifiedJwt($token['access_token']);

        // RFC 9068 §2.1: the type that tells an access token from an ID token.
        self::assertSame('at+jwt', $jwt['header']['typ']);
        self::assertSame('RS256', $jwt['header']['alg']);
        self::assertIsString($jwt['header']['kid']);

        // RFC 9068 §2.2: every required claim. With no resource owner, `sub` is the client.
        $claims = $jwt['claims'];
        self::assertSame('https://auth.clavia.test', $claims['iss']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $claims['aud']);
        self::assertSame(self::TEST_M2M_CLIENT_ID, $claims['sub']);
        self::assertSame(self::TEST_M2M_CLIENT_ID, $claims['client_id']);
        self::assertSame(self::TEST_M2M_SCOPE, $claims['scope']);
        self::assertIsInt($claims['iat']);
        self::assertIsInt($claims['exp']);
        self::assertSame(
            $this->container()->get(Settings::class)->accessTokenLifetime,
            $claims['exp'] - $claims['iat'],
        );
        self::assertIsString($claims['jti']);
        // The token response is what it always was.
        self::assertSame('Bearer', self::json($response)['token_type']);
        // Recorded by the digest of the JWT, as any token is by the digest of its value.
        $row = $this->onlyRow('oauth2_access_tokens');
        self::assertSame($claims['jti'], $row['id']);
        self::assertSame(Digest::of($token['access_token'])->toString(), $row['token_hash']);
    }

    public function testAPersonsTokenNamesThePersonAndTheClient(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $this->jwtApi($this->machineApi());

        $response = $this->userToken('openid api:read');
        $claims = $this->verifiedJwt($response['access_token'])['claims'];

        self::assertSame($user->id->value, $claims['sub']);
        self::assertSame(self::TEST_CLIENT_ID, $claims['client_id']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $claims['aud']);
        self::assertEqualsCanonicalizing(['openid', 'api:read'], explode(' ', (string) $claims['scope']));
        // Identity claims stay at userinfo (RFC 9068 §2.2.2 makes them optional).
        self::assertArrayNotHasKey('email', $claims);
        // And the ID token's `at_hash` is the hash of the JWT, the token the client holds.
        $idToken = $this->verifiedIdToken($response['id_token']);
        self::assertSame(self::atHash($response['access_token']), $idToken['claims']['at_hash']);
        self::assertSame(200, $this->userinfo($response['access_token'])->getStatusCode());
    }

    public function testARefreshedTokenIsAJwtToo(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $this->jwtApi($this->machineApi());
        $first = $this->userToken('openid api:read');

        $refreshed = self::issued($this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => (string) $first['refresh_token'],
        ]));

        $claims = $this->verifiedJwt($refreshed['access_token'])['claims'];
        self::assertSame(self::TEST_M2M_AUDIENCE, $claims['aud']);
        self::assertNotSame($this->verifiedJwt($first['access_token'])['claims']['jti'], $claims['jti']);
    }

    public function testATokenForNoApiStaysOpaque(): void
    {
        // RFC 9068 §2.2 requires an `aud`; a sign-in naming no API has none to give.
        $this->loggedIn();
        $this->publicClient();
        $this->jwtApi($this->machineApi());

        $token = $this->userToken('openid profile', audience: null);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $token['access_token']);
    }

    public function testRevokingAJwtReachesEverySurfaceOfThisServer(): void
    {
        // What an API validating the JWT on its own will not see — it keeps accepting the
        // token until `exp` — this server sees at once.
        $this->loggedIn();
        $this->publicClient();
        $this->jwtApi($this->machineApi());
        $token = $this->userToken('openid api:read');
        self::assertTrue(self::json($this->introspect($token['access_token']))['active']);

        $revoked = $this->post('/oauth2/revoke', [
            'token' => $token['access_token'],
            'client_id' => self::TEST_CLIENT_ID,
        ]);

        self::assertSame(200, $revoked->getStatusCode());
        self::assertSame(['active' => false], self::json($this->introspect($token['access_token'])));
        self::assertSame(401, $this->userinfo($token['access_token'])->getStatusCode());
    }

    public function testNoActiveKeyIssuesNothing(): void
    {
        // A JWT API with no key to sign: a loud failure, and nothing recorded.
        $this->jwtApi($this->machineApi());
        TestStorage::database()->execute('DELETE FROM oidc_signing_keys');

        $response = $this->requestMachineToken();

        self::assertSame(500, $response->getStatusCode());
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    private function jwtApi(ResourceServer $api): void
    {
        $this->container()->get(ResourceServerRepository::class)
            ->save($api->issuingAccessTokensAs(AccessTokenFormat::Jwt));
    }

    /**
     * Sign in as the auto-logged-in user, naming the machine API unless told otherwise.
     *
     * @return array{access_token: string, refresh_token: string|null, id_token: mixed}
     */
    private function userToken(string $scope, ?string $audience = self::TEST_M2M_AUDIENCE): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => $scope, 'audience' => $audience]);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        return self::issued($response) + ['id_token' => self::json($response)['id_token'] ?? null];
    }

    /** @return array{access_token: string, refresh_token: string|null} */
    private static function issued(ResponseInterface $response): array
    {
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response);
        self::assertIsString($token['access_token']);
        $hasRefresh = isset($token['refresh_token']) && is_string($token['refresh_token']);

        return [
            'access_token' => $token['access_token'],
            'refresh_token' => $hasRefresh ? $token['refresh_token'] : null,
        ];
    }

    /** OIDC Core §3.1.3.6, for RS256: the left half of the SHA-256, base64url. */
    private static function atHash(string $accessToken): string
    {
        return rtrim(strtr(base64_encode(substr(hash('sha256', $accessToken, true), 0, 16)), '+/', '-_'), '=');
    }

    private function introspect(string $token): ResponseInterface
    {
        return $this->post(
            '/oauth2/introspect',
            ['token' => $token],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );
    }

    private function userinfo(string $accessToken): ResponseInterface
    {
        return $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Bearer ' . $accessToken]);
    }
}
