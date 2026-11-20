<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestEnvironment;

/**
 * The Authorization Code + PKCE flow, end to end.
 *
 * Ported from `tests/test_authorization_code_flow.py`, test for test.
 */
final class AuthorizationCodeFlowTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    public function testAuthorizeIssuesCodeAndPreservesState(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));

        self::assertSame(302, $response->getStatusCode());
        $location = $response->getHeaderLine('Location');
        $query = self::locationQuery($response);

        self::assertSame(self::TEST_REDIRECT_URI, strtok($location, '?'));
        self::assertNotEmpty($query['code']);
        // The state must round-trip untouched; it is the client's CSRF defence.
        self::assertSame('test-state-value', $query['state']);
        // RFC 9207: the response names the server that issued it.
        self::assertSame('https://auth.' . TestEnvironment::ROOT_DOMAIN, $query['iss']);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testAuthorizationCodeIsNotStoredInPlaintext(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $code = $this->authorizeAndGetCode($challenge);

        $stored = $this->onlyRow('oauth2_authorization_codes');
        self::assertSame(Digest::of($code)->toString(), $stored['code_hash']);
        self::assertStringNotContainsString($code, (string) json_encode($stored));
        self::assertSame($challenge, $stored['code_challenge']);
        self::assertSame('S256', $stored['code_challenge_method']);
        self::assertNull($stored['used_at']);
    }

    public function testFullFlowExchangesCodeForAccessToken(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();

        $code = $this->authorizeAndGetCode($challenge);

        $tokenResponse = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(200, $tokenResponse->getStatusCode(), (string) $tokenResponse->getBody());
        // RFC 6749 §5.1: a token response must not be cached.
        self::assertSame('no-store', $tokenResponse->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $tokenResponse->getHeaderLine('Pragma'));
        $payload = self::json($tokenResponse);
        self::assertSame('Bearer', $payload['token_type']);
        self::assertIsString($payload['access_token']);
        self::assertNotSame('', $payload['access_token']);
        self::assertGreaterThan(0, $payload['expires_in']);
        self::assertIsString($payload['scope']);
        self::assertEqualsCanonicalizing(['openid', 'profile'], explode(' ', $payload['scope']));
        // A refresh token is opt-in per client, and this one is registered for the
        // authorization code grant alone.
        self::assertArrayNotHasKey('refresh_token', $payload);

        $stored = $this->onlyRow('oauth2_access_tokens');
        self::assertSame(Digest::of($payload['access_token'])->toString(), $stored['token_hash']);
        self::assertSame($user->id->value, $stored['user_id']);
        self::assertNull($stored['revoked_at']);
        // The link back to the originating code is what makes replay revocation possible.
        self::assertSame($this->onlyRow('oauth2_authorization_codes')['id'], $stored['authorization_code_id']);
    }

    public function testCodeIsMarkedConsumedAfterExchange(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertNotNull($this->onlyRow('oauth2_authorization_codes')['used_at']);
    }

    /** PKCE is required of a confidential client too, in addition to its secret. */
    public function testConfidentialClientCompletesTheFlowWithItsSecret(): void
    {
        $this->loggedIn();
        $this->confidentialClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
        ]));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    }

    /**
     * A scope this server does not support fails outright rather than being dropped.
     *
     * RFC 6749 §3.3 permits either ignoring an unrecognised scope or failing with
     * `invalid_scope`. Failing is the stricter reading and surfaces client
     * misconfiguration instead of silently issuing a token weaker than the one asked for.
     */
    public function testScopeUnknownToTheServerIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['scope' => 'openid profile admin']),
        );

        self::assertSame(302, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertArrayNotHasKey('code', $query);
        self::assertSame('invalid_scope', $query['error']);
        self::assertSame('test-state-value', $query['state']);
    }

    /**
     * A client holds no scope of its own, so nothing on it narrows the request.
     *
     * The OIDC scopes describe the user and are the user's to delegate; the client is
     * only the conduit.
     */
    public function testEveryOidcScopeMayBeRequestedByAnyClient(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => 'openid profile email']);

        $tokenResponse = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(200, $tokenResponse->getStatusCode(), (string) $tokenResponse->getBody());
        $granted = explode(' ', (string) (self::json($tokenResponse)['scope'] ?? ''));
        self::assertEqualsCanonicalizing(['openid', 'profile', 'email'], $granted);
    }

    /**
     * No session and no dev auto-login: the request is valid but nobody is signed in.
     *
     * The user is sent to the login page — never bounced back to the client with an error.
     */
    public function testAuthorizeWithoutAuthenticatedUserRedirectsToLogin(): void
    {
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge));

        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?', $response->getHeaderLine('Location'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testHealthz(): void
    {
        self::assertSame(200, $this->get('/healthz')->getStatusCode());
    }
}
