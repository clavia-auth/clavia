<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Psr\Http\Message\ResponseInterface;

/**
 * Token introspection (RFC 7662) and revocation (RFC 7009) — ported from the Python
 * suite's `test_introspection_revocation.py`.
 *
 * Introspection is a question only a client holding a secret may ask, answered truthfully
 * only about tokens it has a stake in: its own, or those issued for an API it holds a
 * grant on. Revocation is any client giving back what it holds; a refresh token takes its
 * family along.
 */
final class IntrospectionRevocationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;

    // ── Introspection ───────────────────────────────────────────────────────────

    public function testAClientIntrospectsItsOwnToken(): void
    {
        $this->machineApi();
        $issued = $this->machineToken();

        $response = $this->introspect($issued['access_token']);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = self::json($response);
        self::assertTrue($body['active']);
        self::assertSame(self::TEST_M2M_CLIENT_ID, $body['client_id']);
        self::assertSame('Bearer', $body['token_type']);
        self::assertSame(self::TEST_M2M_SCOPE, $body['scope']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $body['aud']);
        self::assertSame('https://auth.clavia.test', $body['iss']);
        self::assertIsInt($body['exp']);
        self::assertIsInt($body['iat']);
        self::assertGreaterThan($body['iat'], $body['exp']);
        // A machine token has no subject, and says so by having none.
        self::assertArrayNotHasKey('sub', $body);
        self::assertArrayNotHasKey('username', $body);
    }

    public function testAnApiIntrospectsTheTokensIssuedForIt(): void
    {
        // The API's own machine client, asking about a person's token presented to it.
        $user = $this->loggedIn();
        $this->machineApi();
        $this->publicClient();
        $issued = $this->userToken('openid api:read', self::TEST_M2M_AUDIENCE);

        $body = self::json($this->introspect($issued['access_token']));

        self::assertTrue($body['active']);
        self::assertSame(self::TEST_CLIENT_ID, $body['client_id']);
        self::assertSame($user->id->value, $body['sub']);
        self::assertSame($user->email, $body['username']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $body['aud']);
        self::assertEqualsCanonicalizing(['openid', 'api:read'], explode(' ', (string) $body['scope']));
    }

    public function testATokenTheCallerHasNoStakeInLooksUnknown(): void
    {
        // Issued to another client, for no API the caller holds a grant on.
        $this->loggedIn();
        $this->machineApi();
        $this->publicClient();
        $issued = $this->userToken();

        self::assertSame(['active' => false], self::json($this->introspect($issued['access_token'])));
    }

    public function testAPublicClientCannotIntrospect(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $issued = $this->userToken();

        $response = $this->post(
            '/oauth2/introspect',
            ['token' => $issued['access_token'], 'client_id' => self::TEST_CLIENT_ID],
        );

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
    }

    public function testAConfidentialClientWithoutAStakeLearnsNothing(): void
    {
        $this->machineApi();
        $this->confidentialClient();
        $issued = $this->machineToken();

        $response = $this->post('/oauth2/introspect', [
            'token' => $issued['access_token'],
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
        ]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['active' => false], self::json($response));
    }

    public function testExpiredRevokedAndUnknownTokensAreInactive(): void
    {
        $this->machineApi();
        $issued = $this->machineToken();
        $database = TestStorage::database();

        $database->execute('UPDATE oauth2_access_tokens SET revoked_at = now()');
        self::assertSame(['active' => false], self::json($this->introspect($issued['access_token'])));

        $database->execute(
            "UPDATE oauth2_access_tokens SET revoked_at = NULL, expires_at = now() - interval '1 second'",
        );
        self::assertSame(['active' => false], self::json($this->introspect($issued['access_token'])));

        self::assertSame(['active' => false], self::json($this->introspect('never-issued')));
    }

    public function testATokenOfADeactivatedAccountIsInactive(): void
    {
        $user = $this->loggedIn();
        $this->machineApi();
        $this->publicClient();
        $issued = $this->userToken('openid api:read', self::TEST_M2M_AUDIENCE);

        $user->deactivate($this->container()->get(Clock::class)->now());
        $this->container()->get(UserRepository::class)->save($user);

        self::assertSame(['active' => false], self::json($this->introspect($issued['access_token'])));
    }

    public function testARefreshTokenIsIntrospectedAndASpentOneIsInactive(): void
    {
        $this->loggedIn();
        $this->machineApi();
        $this->refreshingClient();
        $issued = $this->userToken('openid api:read', self::TEST_M2M_AUDIENCE);
        $refreshToken = (string) $issued['refresh_token'];

        $body = self::json($this->introspect($refreshToken, 'refresh_token'));
        self::assertTrue($body['active']);
        self::assertSame(self::TEST_CLIENT_ID, $body['client_id']);
        self::assertArrayNotHasKey('token_type', $body);

        // Rotated: the old one is spent, and reads as dead whatever the hint says.
        self::assertSame(200, $this->refresh($refreshToken)->getStatusCode());
        self::assertSame(['active' => false], self::json($this->introspect($refreshToken)));
        self::assertSame(['active' => false], self::json($this->introspect($refreshToken, 'refresh_token')));
    }

    public function testTheHintIsAnOptimisationNotAConstraint(): void
    {
        $this->machineApi();
        $issued = $this->machineToken();

        self::assertTrue(self::json($this->introspect($issued['access_token'], 'refresh_token'))['active']);
    }

    public function testMalformedIntrospectionRequests(): void
    {
        $this->machineApi();
        $credentials = [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET];

        $missing = $this->post('/oauth2/introspect', [], basicAuth: $credentials);
        self::assertSame(400, $missing->getStatusCode());
        self::assertSame('invalid_request', self::json($missing)['error']);

        $badHint = $this->introspect('x', 'id_token');
        self::assertSame(400, $badHint->getStatusCode());
        self::assertSame('unsupported_token_type', self::json($badHint)['error']);

        $repeated = $this->request(
            'POST',
            '/oauth2/introspect',
            [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => 'Basic ' . base64_encode(implode(':', $credentials)),
            ],
            body: 'token=a&token=b',
        );
        self::assertSame(400, $repeated->getStatusCode());
        self::assertSame('invalid_request', self::json($repeated)['error']);

        $anonymous = $this->post('/oauth2/introspect', ['token' => 'x']);
        self::assertSame(401, $anonymous->getStatusCode());
        self::assertStringStartsWith('Basic realm=', $anonymous->getHeaderLine('WWW-Authenticate'));
    }

    // ── Revocation ──────────────────────────────────────────────────────────────

    public function testAPublicClientRevokesItsOwnAccessToken(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $issued = $this->userToken();
        self::assertSame(200, $this->userinfo($issued['access_token'])->getStatusCode());

        $response = $this->revoke($issued['access_token'], ['client_id' => self::TEST_CLIENT_ID]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('', (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame(401, $this->userinfo($issued['access_token'])->getStatusCode());
    }

    public function testRevokingARefreshTokenRevokesTheWholeFamily(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $first = $this->userToken();
        $second = self::json($this->refresh((string) $first['refresh_token']));

        $response = $this->revoke(
            (string) $second['refresh_token'],
            ['client_id' => self::TEST_CLIENT_ID, 'token_type_hint' => 'refresh_token'],
        );

        self::assertSame(200, $response->getStatusCode());
        // Every refresh token in the chain, and every access token any of them minted.
        self::assertSame(
            0,
            TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_refresh_tokens WHERE revoked_at IS NULL'),
        );
        self::assertSame(401, $this->userinfo($first['access_token'])->getStatusCode());
        self::assertSame(401, $this->userinfo((string) $second['access_token'])->getStatusCode());
        self::assertSame('invalid_grant', self::json($this->refresh((string) $second['refresh_token']))['error']);
    }

    public function testRevokingAnAccessTokenLeavesTheRefreshTokenAlone(): void
    {
        // The client may well be keeping its session: taking it would be more than asked.
        $this->loggedIn();
        $this->refreshingClient();
        $issued = $this->userToken();

        self::assertSame(
            200,
            $this->revoke($issued['access_token'], ['client_id' => self::TEST_CLIENT_ID])->getStatusCode(),
        );

        self::assertSame(401, $this->userinfo($issued['access_token'])->getStatusCode());
        $renewed = $this->refresh((string) $issued['refresh_token']);
        self::assertSame(200, $renewed->getStatusCode(), (string) $renewed->getBody());
    }

    public function testAMachineClientRevokesWithItsSecret(): void
    {
        $this->machineApi();
        $issued = $this->machineToken();

        $response = $this->revoke($issued['access_token'], [], [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['active' => false], self::json($this->introspect($issued['access_token'])));
    }

    public function testAnotherClientsTokenIsNotRevoked(): void
    {
        $this->loggedIn();
        $this->machineApi();
        $this->publicClient();
        $issued = $this->userToken();

        $response = $this->revoke($issued['access_token'], [], [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertSame(200, $this->userinfo($issued['access_token'])->getStatusCode());
    }

    public function testAnUnknownTokenIsRevokedQuietly(): void
    {
        // RFC 7009 §2.2: an invalid token is still a 200 — there is nothing to reveal.
        $this->publicClient();

        self::assertSame(200, $this->revoke('never-issued', ['client_id' => self::TEST_CLIENT_ID])->getStatusCode());
    }

    public function testRevocationNeedsAClient(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $issued = $this->userToken();

        $response = $this->revoke($issued['access_token']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
        self::assertSame(200, $this->userinfo($issued['access_token'])->getStatusCode());
    }

    public function testDiscoveryAdvertisesBothEndpoints(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame('https://auth.clavia.test/oauth2/introspect', $document['introspection_endpoint']);
        self::assertSame('https://auth.clavia.test/oauth2/revoke', $document['revocation_endpoint']);
        self::assertSame(
            ['client_secret_basic', 'client_secret_post'],
            $document['introspection_endpoint_auth_methods_supported'],
        );
        self::assertSame(
            ['client_secret_basic', 'client_secret_post', 'none'],
            $document['revocation_endpoint_auth_methods_supported'],
        );
        self::assertSame(
            $document,
            self::json($this->get('/.well-known/oauth-authorization-server')),
            'RFC 8414 metadata says the same.',
        );
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /** @return array{access_token: string, refresh_token: string|null} */
    private function machineToken(): array
    {
        return self::issued($this->requestMachineToken());
    }

    /**
     * Sign in as the auto-logged-in user with the public client.
     *
     * @return array{access_token: string, refresh_token: string|null}
     */
    private function userToken(string $scope = 'openid profile', ?string $audience = null): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => $scope, 'audience' => $audience]);

        return self::issued($this->post('/oauth2/token', $this->tokenRequest($code, $verifier)));
    }

    /** @return array{access_token: string, refresh_token: string|null} */
    private static function issued(ResponseInterface $response): array
    {
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response);
        $accessToken = $token['access_token'] ?? null;
        /** @var mixed $refreshToken Absent unless the client is registered for refresh tokens. */
        $refreshToken = $token['refresh_token'] ?? null;
        self::assertIsString($accessToken);

        return ['access_token' => $accessToken, 'refresh_token' => is_string($refreshToken) ? $refreshToken : null];
    }

    private function introspect(string $token, ?string $hint = null): ResponseInterface
    {
        $form = ['token' => $token];
        if ($hint !== null) {
            $form['token_type_hint'] = $hint;
        }

        return $this->post('/oauth2/introspect', $form, basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET]);
    }

    /**
     * @param array<string, string>      $form
     * @param array{string, string}|null $basicAuth
     */
    private function revoke(string $token, array $form = [], ?array $basicAuth = null): ResponseInterface
    {
        return $this->post('/oauth2/revoke', ['token' => $token] + $form, basicAuth: $basicAuth);
    }

    private function refresh(string $refreshToken): ResponseInterface
    {
        return $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => $refreshToken,
        ]);
    }

    private function userinfo(string $accessToken): ResponseInterface
    {
        return $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Bearer ' . $accessToken]);
    }
}
