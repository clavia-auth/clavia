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
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Negative cases for the Authorization Code + PKCE flow.
 *
 * Each test here corresponds to an attack the protocol is meant to stop, so a failure in
 * this file means a security regression rather than a broken feature.
 */
final class PkceSecurityTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    // ------------------------------------------------------------------
    // PKCE is mandatory, and S256 only
    // ------------------------------------------------------------------

    public function testAuthorizeWithoutPkceIsRejectedForPublicClient(): void
    {
        $this->loggedIn();
        $this->publicClient();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams(null));

        $this->assertRejected($response, 'invalid_request');
    }

    /** PKCE is required of every client, not just public ones. */
    public function testAuthorizeWithoutPkceIsRejectedForConfidentialClient(): void
    {
        $this->loggedIn();
        $this->confidentialClient();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams(null, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]),
        );

        $this->assertRejected($response, 'invalid_request');
    }

    // ------------------------------------------------------------------
    // OAuth 2.1 §7.5.1: a confidential client relieved of PKCE, bound by its nonce
    // ------------------------------------------------------------------

    public function testAConfidentialClientRelievedOfPkceSignsInWithANonceAlone(): void
    {
        $this->loggedIn();
        $this->register($this->confidentialClient()->withPkceRequired(false));

        $code = $this->extractCode($this->get('/oauth2/authorize', $this->authorizeParams(null, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'nonce' => 'n-0S6_WzA2Mj',
        ])));
        $response = $this->post('/oauth2/token', $this->confidentialTokenRequest($code));

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertArrayHasKey('id_token', self::json($response));
    }

    public function testWithoutANonceTheExemptionDoesNotApply(): void
    {
        $this->loggedIn();
        $this->register($this->confidentialClient()->withPkceRequired(false));

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams(null, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]),
        );

        $this->assertRejected($response, 'invalid_request');
        self::assertStringContainsString("unless an OpenID Connect request carries a 'nonce'", self::locationQuery(
            $response,
        )['error_description'] ?? '');
    }

    public function testAVerifierForACodeIssuedWithoutPkceIsRefused(): void
    {
        // OAuth 2.1 §4.1.3: accepting one would let a downgrade pass for PKCE.
        $this->loggedIn();
        $this->register($this->confidentialClient()->withPkceRequired(false));
        $code = $this->extractCode($this->get('/oauth2/authorize', $this->authorizeParams(null, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'nonce' => 'n-0S6_WzA2Mj',
        ])));

        $response = $this->post('/oauth2/token', $this->confidentialTokenRequest($code, str_repeat('v', 43)));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error'] ?? null);
    }

    public function testAChallengeARelievedClientSendsIsCheckedLikeAnyOther(): void
    {
        $this->loggedIn();
        $this->register($this->confidentialClient()->withPkceRequired(false));
        [, $challenge] = $this->makePkcePair();
        $code = $this->extractCode($this->get('/oauth2/authorize', $this->authorizeParams($challenge, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'nonce' => 'n-0S6_WzA2Mj',
        ])));

        $response = $this->post('/oauth2/token', $this->confidentialTokenRequest($code));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_request', self::json($response)['error'] ?? null, 'The verifier is missing.');
    }

    /** `plain` offers no protection against a stolen challenge and must be refused. */
    public function testPlainChallengeMethodIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams(
            $verifier, // for 'plain', challenge == verifier
            ['code_challenge_method' => 'plain'],
        ));

        $this->assertRejected($response, 'invalid_request');
    }

    /**
     * Guards the silent downgrade path: RFC 7636 defaults an absent
     * `code_challenge_method` to `plain`, so omitting it must never be accepted.
     */
    public function testMissingChallengeMethodIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['code_challenge_method' => null]),
        );

        $this->assertRejected($response, 'invalid_request');
    }

    public function testWrongCodeVerifierIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();
        [$otherVerifier] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $otherVerifier));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testMissingCodeVerifierIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, null));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertContains(self::json($response)['error'], ['invalid_request', 'invalid_grant']);
    }

    // ------------------------------------------------------------------
    // Single-use codes and replay detection
    // ------------------------------------------------------------------

    /**
     * RFC 6749 §4.1.2: a code seen twice has leaked.
     *
     * The second request must be denied *and* every token the code already produced must
     * be revoked, since we cannot tell which of the two callers was legitimate.
     */
    public function testReplayedCodeIsRejectedAndRevokesIssuedTokens(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);
        $payload = $this->tokenRequest($code, $verifier);

        $first = $this->post('/oauth2/token', $payload);
        self::assertSame(StatusCodeInterface::STATUS_OK, $first->getStatusCode(), (string) $first->getBody());

        $second = $this->post('/oauth2/token', $payload);
        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $second->getStatusCode());
        self::assertSame('invalid_grant', self::json($second)['error']);

        $token = $this->onlyRow('oauth2_access_tokens');
        self::assertNotNull($token['revoked_at'], 'replay must revoke the token the code produced');
    }

    public function testExpiredCodeIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);
        $this->expireTheCode();

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * An expired code is refused without being marked used.
     *
     * Only a genuine redemption should burn a code, so that the `used_at` marker means
     * "replayed" and not merely "seen".
     */
    public function testExpiredCodeIsNotConsumed(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);
        $this->expireTheCode();

        $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertNull($this->onlyRow('oauth2_authorization_codes')['used_at']);
    }

    /** A code is bound to the client it was issued to. */
    public function testCodeCannotBeRedeemedByADifferentClient(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->confidentialClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
        ]));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        // Presenting someone else's code tells the presenter nothing and costs its owner nothing.
        self::assertNull($this->onlyRow('oauth2_authorization_codes')['used_at']);
    }

    // ------------------------------------------------------------------
    // Client authentication
    // ------------------------------------------------------------------

    /**
     * A failed client authentication is a 401 carrying `WWW-Authenticate`.
     *
     * RFC 7235 §3.1 requires the header on every 401, and RFC 6749 §5.2 specifically
     * when the client authenticates through the `Authorization` header.
     */
    public function testWrongClientSecretIsRejectedWithAChallenge(): void
    {
        $this->loggedIn();
        $this->confidentialClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]);

        $response = $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]),
            basicAuth: [self::TEST_CONFIDENTIAL_CLIENT_ID, 'not-the-secret'],
        );

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
        self::assertStringStartsWith('Basic ', $response->getHeaderLine('WWW-Authenticate'));
        // A failed authentication must not cost the legitimate client its code.
        self::assertNull($this->onlyRow('oauth2_authorization_codes')['used_at']);
    }

    // ------------------------------------------------------------------
    // Redirect URI handling
    // ------------------------------------------------------------------

    /**
     * The open-redirect case.
     *
     * An unregistered `redirect_uri` must produce a local error. Redirecting to it —
     * even to report an error — would turn the authorization endpoint into an open
     * redirector and hand authorization codes to whoever supplied the URI.
     */
    public function testUnregisteredRedirectUriDoesNotRedirect(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['redirect_uri' => 'https://attacker.test/steal']),
        );

        self::assertNotSame(
            StatusCodeInterface::STATUS_FOUND,
            $response->getStatusCode(),
            'must not redirect to an unregistered URI',
        );
        self::assertStringNotContainsString('attacker.test', $response->getHeaderLine('Location'));
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_authorization_codes'));
    }

    /** The redirect URI presented at redemption must match the one bound to the code. */
    public function testRedirectUriMustMatchAtTokenEndpoint(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $response = $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier, ['redirect_uri' => 'https://client.test/other-callback']),
        );

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * With nobody signed in, an unknown client is still refused outright.
     *
     * Validation runs before the user is resolved, so the endpoint never becomes a
     * phishing surface that shows a login page for attacker-supplied parameters.
     */
    public function testUnknownClientIsRejectedBeforeAnyoneIsAskedToSignIn(): void
    {
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['client_id' => 'no-such-client']),
        );

        $this->assertRejected($response, 'invalid_client');
        self::assertSame('', $response->getHeaderLine('Location'));
    }

    public function testUnknownCodeIsRejected(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier] = $this->makePkcePair();

        $response = $this->post('/oauth2/token', $this->tokenRequest('not-a-real-code', $verifier));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    /** Deactivating an account between authorization and redemption must block the token. */
    public function testInactiveUserCannotRedeemCode(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        /** @var UserRepository $users */
        $users = $this->container()->get(UserRepository::class);
        /** @var Clock $clock */
        $clock = $this->container()->get(Clock::class);
        $user->deactivate($clock->now());
        $users->save($user);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertGreaterThanOrEqual(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    /**
     * Assert no authorization code was issued, and that the OAuth2 error is the expected one —
     * whether it came back as a redirect to the client or as a local error.
     */
    private function assertRejected(ResponseInterface $response, string $expectedError): void
    {
        if ($response->getStatusCode() === StatusCodeInterface::STATUS_FOUND) {
            $query = self::locationQuery($response);
            self::assertArrayNotHasKey('code', $query, 'an authorization code was issued');
            $error = $query['error'] ?? null;
        } else {
            self::assertGreaterThanOrEqual(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                $response->getStatusCode(),
                (string) $response->getBody(),
            );
            /** @var mixed $error */
            $error = self::json($response)['error'] ?? null;
        }

        self::assertSame($expectedError, $error);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_authorization_codes'));
    }

    private function expireTheCode(): void
    {
        TestStorage::database()->execute(
            "UPDATE oauth2_authorization_codes SET expires_at = now() - interval '1 second'",
        );
    }

    /**
     * The confidential client's token request, authenticated with its secret.
     *
     * @return array<string, string>
     */
    private function confidentialTokenRequest(string $code, ?string $verifier = null): array
    {
        return $this->tokenRequest($code, $verifier, [
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
        ]);
    }
}
