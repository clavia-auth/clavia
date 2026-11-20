<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Base64Url;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * The OpenID Connect layer: discovery, the JWKS, ID tokens and userinfo — ported from
 * the Python suite's `test_oidc.py`.
 *
 * A relying party trusts nothing but the JWKS, so ID tokens are verified the way one
 * would: with the keys published over HTTP, never by reading the database.
 */
final class OidcTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use OidcFixtures;

    private const string ISSUER = 'https://auth.' . TestEnvironment::ROOT_DOMAIN;

    // ── Discovery and JWKS ──────────────────────────────────────────────────────

    public function testDiscoveryDocument(): void
    {
        $response = $this->get('/.well-known/openid-configuration');
        $document = self::json($response);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(self::ISSUER, $document['issuer']);
        self::assertSame(self::ISSUER . '/oauth2/authorize', $document['authorization_endpoint']);
        self::assertSame(self::ISSUER . '/oauth2/token', $document['token_endpoint']);
        self::assertSame(self::ISSUER . '/oidc/userinfo', $document['userinfo_endpoint']);
        self::assertSame(self::ISSUER . '/oidc/jwks.json', $document['jwks_uri']);
        self::assertSame(self::ISSUER . '/oidc/logout', $document['end_session_endpoint']);
        self::assertSame(['RS256'], $document['id_token_signing_alg_values_supported']);
        // PKCE is mandatory here, so `plain` is not advertised.
        self::assertSame(['S256'], $document['code_challenge_methods_supported']);
        // Only the grants that exist: clients trust this document.
        self::assertSame(['authorization_code', 'client_credentials'], $document['grant_types_supported']);
        self::assertSame(['code'], $document['response_types_supported']);
        self::assertSame(['query'], $document['response_modes_supported']);
        self::assertSame(['public'], $document['subject_types_supported']);
        self::assertSame(['openid', 'profile', 'email'], $document['scopes_supported']);
        self::assertSame(
            ['client_secret_basic', 'client_secret_post', 'none'],
            $document['token_endpoint_auth_methods_supported'],
        );
        self::assertSame('public, max-age=3600', $response->getHeaderLine('Cache-Control'));

        // Stated because the specification's default is the opposite of what this server does.
        self::assertFalse($document['request_uri_parameter_supported']);
        self::assertFalse($document['request_parameter_supported']);
        self::assertFalse($document['claims_parameter_supported']);
        self::assertSame(['normal'], $document['claim_types_supported']);
        self::assertTrue($document['authorization_response_iss_parameter_supported']);
        $claims = $document['claims_supported'];
        self::assertIsArray($claims);
        foreach (['sub', 'auth_time', 'nonce', 'amr', 'at_hash', 'email', 'email_verified', 'name'] as $claim) {
            self::assertContains($claim, $claims);
        }

        // Nothing is advertised that does not exist yet.
        self::assertArrayNotHasKey('prompt_values_supported', $document);
        self::assertArrayNotHasKey('introspection_endpoint', $document);
        self::assertNotContains('sid', $claims);
    }

    public function testRfc8414MetadataIsTheSameDocument(): void
    {
        // An OAuth client looks at a different well-known path than an OpenID relying
        // party (RFC 8414 §3); both must find the same answer.
        $oidc = $this->get('/.well-known/openid-configuration');
        $oauth = $this->get('/.well-known/oauth-authorization-server');

        self::assertSame(200, $oauth->getStatusCode());
        self::assertSame(self::json($oidc), self::json($oauth));
        self::assertSame($oidc->getHeaderLine('Cache-Control'), $oauth->getHeaderLine('Cache-Control'));
    }

    public function testDiscoveryAdvertisesOnlyWorkingEndpoints(): void
    {
        // A relying party takes the document as the contract; a URL in it that answers
        // 404 breaks the contract at the worst possible moment.
        $document = self::json($this->get('/.well-known/openid-configuration'));

        $advertised = [];
        foreach (array_keys($document) as $field) {
            $field = (string) $field;
            /** @var mixed $url */
            $url = $document[$field];
            if (is_string($url) && (str_ends_with($field, '_endpoint') || str_ends_with($field, '_uri'))) {
                $advertised[$field] = $url;
            }
        }
        self::assertCount(5, $advertised);

        foreach ($advertised as $field => $url) {
            self::assertStringStartsWith(self::ISSUER . '/', $url, $field);
            $path = substr($url, strlen(self::ISSUER));

            self::assertNotSame(404, $this->get($path)->getStatusCode(), "{$field} points at a 404");
        }
    }

    public function testJwksNeverExposesPrivateComponents(): void
    {
        $keys = self::json($this->get('/oidc/jwks.json'))['keys'];

        self::assertIsArray($keys);
        self::assertNotEmpty($keys, 'no keys published');
        foreach ($keys as $key) {
            self::assertIsArray($key);
            self::assertSame('RSA', $key['kty']);
            self::assertSame('sig', $key['use']);
            self::assertSame('RS256', $key['alg']);
            self::assertNotEmpty($key['kid']);
            // The RSA private components. Leaking any one of them hands over the ability
            // to mint tokens for the whole deployment.
            foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as $private) {
                self::assertArrayNotHasKey($private, $key, "the JWKS leaked the private member {$private}");
            }
        }
    }

    public function testJwksIsCacheableForTheDocumentedWindow(): void
    {
        // Pinned to the number key rotation is reasoned about through.
        $response = $this->get('/oidc/jwks.json');

        self::assertSame(
            sprintf('public, max-age=%d', PublishSigningKeys::CACHE_MAX_AGE),
            $response->getHeaderLine('Cache-Control'),
        );
    }

    public function testPrivateKeyIsStoredEncrypted(): void
    {
        // A database backup alone must not yield the signing key.
        TestStorage::database()->execute('DELETE FROM oidc_signing_keys');
        $key = $this->container()->get(GenerateSigningKey::class)();

        /** @var string $sealed */
        $sealed = TestStorage::database()->fetchValue(
            'SELECT private_key_encrypted FROM oidc_signing_keys WHERE kid = :kid',
            ['kid' => $key->kid()],
        );
        $cipher = $this->container()->get(SecretCipher::class);

        self::assertStringNotContainsString('PRIVATE KEY', $sealed);
        self::assertStringContainsString('PRIVATE KEY', $cipher->decrypt($sealed, $key->kid()));
    }

    // ── ID tokens ───────────────────────────────────────────────────────────────

    public function testIdTokenIssuedForOpenidScope(): void
    {
        $this->publicClient();
        $this->loggedIn();

        self::assertArrayHasKey('id_token', $this->completeFlow('openid email'));
    }

    public function testNoIdTokenWithoutOpenidScope(): void
    {
        // A plain OAuth2 client asking for no identity gets none.
        $this->publicClient();
        $this->loggedIn();

        self::assertArrayNotHasKey('id_token', $this->completeFlow('profile'));
    }

    public function testIdTokenVerifiesAgainstPublishedJwks(): void
    {
        $this->publicClient();
        $user = $this->loggedIn();

        $token = $this->verifiedIdToken($this->completeFlow()['id_token']);

        self::assertSame('RS256', $token['header']['alg']);
        self::assertSame('JWT', $token['header']['typ']);
        self::assertNotEmpty($token['header']['kid'], 'the header must name the signing key');
        $claims = $token['claims'];
        self::assertSame(self::ISSUER, $claims['iss']);
        self::assertSame(self::TEST_CLIENT_ID, $claims['aud']);
        // `sub` is the stable opaque id, never the email: OIDC forbids reassigning it.
        self::assertSame($user->id->value, $claims['sub']);
        self::assertNotSame($user->email, $claims['sub']);
        self::assertIsInt($claims['iat']);
        self::assertIsInt($claims['exp']);
        self::assertSame(300, $claims['exp'] - $claims['iat']);
    }

    public function testIdTokenCarriesEmailOnlyWhenScoped(): void
    {
        $this->publicClient();
        $user = $this->loggedIn();

        $withEmail = $this->verifiedIdToken($this->completeFlow('openid email')['id_token'])['claims'];
        $withoutEmail = $this->verifiedIdToken($this->completeFlow('openid')['id_token'])['claims'];

        self::assertSame($user->email, $withEmail['email']);
        self::assertFalse($withEmail['email_verified']);
        self::assertArrayNotHasKey('email', $withoutEmail);
        self::assertArrayNotHasKey('email_verified', $withoutEmail);
    }

    public function testIdTokenCarriesProfileClaimsThatAreSet(): void
    {
        // Unset profile fields are absent, not null (OIDC Core §5.1).
        $this->publicClient();
        $this->loggedIn();
        $this->setProfile(Profile::of(name: 'Ada Lovelace', givenName: 'Ada'));

        $claims = $this->verifiedIdToken($this->completeFlow('openid profile')['id_token'])['claims'];

        self::assertSame('Ada Lovelace', $claims['name']);
        self::assertSame('Ada', $claims['given_name']);
        self::assertArrayNotHasKey('family_name', $claims);
        self::assertArrayNotHasKey('picture', $claims);
        self::assertIsInt($claims['updated_at']);
    }

    public function testNonceRoundTripsIntoTheIdToken(): void
    {
        // The nonce is the client's replay defence and must come back verbatim.
        $this->publicClient();
        $this->loggedIn();

        $payload = $this->completeFlow(authorizeOverrides: ['nonce' => 'client-generated-nonce-value']);

        self::assertSame(
            'client-generated-nonce-value',
            $this->verifiedIdToken($payload['id_token'])['claims']['nonce'],
        );
    }

    public function testReplayedNonceIsRefused(): void
    {
        // A captured authorization URL must not mint a second code.
        $this->publicClient();
        $this->loggedIn();
        [, $challenge] = $this->makePkcePair();
        $params = $this->authorizeParams($challenge, ['scope' => 'openid', 'nonce' => 'only-once']);

        $this->extractCode($this->get('/oauth2/authorize', $params));
        $second = $this->get('/oauth2/authorize', $params);

        self::assertSame(302, $second->getStatusCode());
        $query = self::locationQuery($second);
        self::assertArrayNotHasKey('code', $query, 'the nonce was accepted twice');
        self::assertSame('invalid_request', $query['error']);
        self::assertSame('test-state-value', $query['state']);
    }

    public function testAtHashBindsTheIdTokenToTheAccessToken(): void
    {
        // `at_hash` stops an ID token being paired with a different access token.
        $this->publicClient();
        $this->loggedIn();

        $payload = $this->completeFlow();
        $claims = $this->verifiedIdToken($payload['id_token'])['claims'];

        self::assertIsString($payload['access_token']);
        $digest = hash('sha256', $payload['access_token'], true);
        self::assertSame(Base64Url::encode(substr($digest, 0, 16)), $claims['at_hash']);
    }

    public function testAuthTimeReportsTheSessionNotNow(): void
    {
        // A returning person authenticated when they signed in, not when they authorized.
        $clock = $this->freezeClock();
        $this->publicClient();
        $this->user();
        $this->submitLogin();
        $signedInAt = $clock->now()->getTimestamp();

        $clock->advance(120);
        $claims = $this->verifiedIdToken($this->completeFlow()['id_token'])['claims'];

        self::assertSame($signedInAt, $claims['auth_time']);
        self::assertSame($signedInAt + 120, $claims['iat']);
        // RFC 8176: a password was typed.
        self::assertSame(['pwd'], $claims['amr']);
    }

    public function testAuthTimeIsOmittedWhenUnknown(): void
    {
        // The development auto-login never authenticated anyone; "now" would be a lie.
        $this->publicClient();
        $this->loggedIn();

        $claims = $this->verifiedIdToken($this->completeFlow()['id_token'])['claims'];

        self::assertArrayNotHasKey('auth_time', $claims);
        self::assertArrayNotHasKey('amr', $claims);
    }

    // ── Key rotation ────────────────────────────────────────────────────────────

    public function testTokensSurviveRotation(): void
    {
        // A token signed just before a rotation must still verify just after it.
        $this->publicClient();
        $this->loggedIn();
        $payload = $this->completeFlow();
        $originalKid = $this->verifiedIdToken($payload['id_token'])['header']['kid'];
        self::assertIsString($originalKid);

        $this->container()->get(RotateSigningKey::class)();

        // Both keys are published, so the old token still verifies…
        self::assertSame($originalKid, $this->verifiedIdToken($payload['id_token'])['header']['kid']);
        // …and new tokens are signed by the new key.
        $fresh = $this->completeFlow();
        self::assertNotSame($originalKid, $this->verifiedIdToken($fresh['id_token'])['header']['kid']);
    }

    public function testWithdrawnKeysLeaveTheJwks(): void
    {
        // Once a retired key's grace period lapses it stops being published.
        $clock = $this->freezeClock();
        $rotation = $this->container()->get(RotateSigningKey::class)();
        $until = $rotation->retired?->publishedUntil();
        self::assertNotNull($until);

        self::assertSame(
            [$rotation->active->kid(), $rotation->retired?->kid()],
            $this->publishedKids(),
        );

        $clock->setTo($until->format(DATE_ATOM));

        self::assertSame([$rotation->active->kid()], $this->publishedKids());
    }

    public function testIssuingWithoutAKeyFailsLoudly(): void
    {
        // Better to refuse than to conjure a key nobody knows to back up.
        $this->publicClient();
        $this->loggedIn();
        TestStorage::database()->execute('DELETE FROM oidc_signing_keys');

        [$verifier, $challenge] = $this->makePkcePair();
        // The authorization request itself still works; the failure surfaces when a
        // token would have to be signed.
        $code = $this->authorizeAndGetCode($challenge, ['scope' => 'openid']);
        $failed = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(500, $failed->getStatusCode());
        self::assertTrue($this->logger->hasRecordContaining('No active signing key'));
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));

        // Nothing was issued, so nothing was spent: once a key exists, the same code works.
        $this->container()->get(GenerateSigningKey::class)();
        $retried = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));
        self::assertSame(200, $retried->getStatusCode(), (string) $retried->getBody());
        self::assertArrayHasKey('id_token', self::json($retried));
    }

    // ── Userinfo ────────────────────────────────────────────────────────────────

    public function testUserinfoReturnsClaimsForAValidToken(): void
    {
        $this->publicClient();
        $user = $this->loggedIn();
        $payload = $this->completeFlow('openid email');

        $response = $this->userinfo($payload['access_token']);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(
            ['sub' => $user->id->value, 'email' => $user->email, 'email_verified' => false],
            self::json($response),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testUserinfoAgreesWithTheIdToken(): void
    {
        // Both go through one definition of what a scope releases, so they cannot drift.
        $this->publicClient();
        $this->loggedIn();
        $this->setProfile(Profile::of(name: 'Ada Lovelace'));
        $payload = $this->completeFlow('openid profile email');

        $fromUserinfo = self::json($this->userinfo($payload['access_token']));
        $fromIdToken = $this->verifiedIdToken($payload['id_token'])['claims'];

        foreach (['sub', 'name', 'email', 'email_verified', 'updated_at'] as $claim) {
            self::assertSame($fromIdToken[$claim], $fromUserinfo[$claim], $claim);
        }
    }

    public function testUserinfoWithholdsEmailWithoutTheScope(): void
    {
        $this->publicClient();
        $user = $this->loggedIn();
        $payload = $this->completeFlow('openid');

        $response = $this->userinfo($payload['access_token']);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['sub' => $user->id->value], self::json($response));
    }

    public function testUserinfoRejectsAMissingOrUnknownToken(): void
    {
        $missing = $this->get('/oidc/userinfo');
        self::assertSame(401, $missing->getStatusCode());
        // RFC 6750 §3.1: no credentials, so no error code — only the scheme to use.
        self::assertSame(sprintf('Bearer realm="%s"', self::ISSUER), $missing->getHeaderLine('WWW-Authenticate'));

        $unknown = $this->userinfo('nope');
        self::assertSame(401, $unknown->getStatusCode());
        self::assertStringStartsWith(
            sprintf('Bearer realm="%s", error="invalid_token"', self::ISSUER),
            $unknown->getHeaderLine('WWW-Authenticate'),
        );
        self::assertSame('invalid_token', self::json($unknown)['error']);
    }

    public function testUserinfoRejectsARevokedToken(): void
    {
        // Revocation takes effect immediately, not at expiry.
        $this->publicClient();
        $this->loggedIn();
        $payload = $this->completeFlow();
        TestStorage::database()->execute('UPDATE oauth2_access_tokens SET revoked_at = now()');

        self::assertSame(401, $this->userinfo($payload['access_token'])->getStatusCode());
    }

    public function testUserinfoRejectsADeactivatedUser(): void
    {
        $this->publicClient();
        $user = $this->loggedIn();
        $payload = $this->completeFlow();
        $user->deactivate(new DateTimeImmutable());
        $this->container()->get(UserRepository::class)->save($user);

        self::assertSame(401, $this->userinfo($payload['access_token'])->getStatusCode());
    }

    public function testUserinfoRequiresTheOpenidScope(): void
    {
        $this->publicClient();
        $this->loggedIn();
        $payload = $this->completeFlow('profile');

        $response = $this->userinfo($payload['access_token']);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', self::json($response)['error']);
        self::assertStringContainsString('scope="openid"', $response->getHeaderLine('WWW-Authenticate'));
    }

    // ── Beyond the Python suite ─────────────────────────────────────────────────

    public function testUserinfoAnswersAPostAsWellAsAGet(): void
    {
        // OIDC Core §5.3.1: "MUST support the use of the HTTP GET and HTTP POST methods".
        $this->publicClient();
        $user = $this->loggedIn();
        $token = $this->completeFlow('openid')['access_token'];
        self::assertIsString($token);

        $response = $this->post('/oidc/userinfo', headers: ['Authorization' => 'Bearer ' . $token]);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['sub' => $user->id->value], self::json($response));
    }

    public function testUserinfoRefusesAMalformedRequestAsSuch(): void
    {
        $this->publicClient();
        $this->loggedIn();
        $payload = $this->completeFlow('openid');
        self::assertIsString($payload['access_token']);

        $malformed = $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Bearer two tokens']);
        self::assertSame(400, $malformed->getStatusCode());
        self::assertSame('invalid_request', self::json($malformed)['error']);

        // RFC 6750 §2: one way of sending the token per request.
        $twice = $this->request(
            'GET',
            '/oidc/userinfo?access_token=' . rawurlencode($payload['access_token']),
            ['Authorization' => 'Bearer ' . $payload['access_token']],
        );
        self::assertSame(400, $twice->getStatusCode());

        // Another scheme is not bearer credentials at all.
        $basic = $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Basic ' . base64_encode('a:b')]);
        self::assertSame(401, $basic->getStatusCode());
        self::assertSame(sprintf('Bearer realm="%s"', self::ISSUER), $basic->getHeaderLine('WWW-Authenticate'));
    }

    public function testUserinfoAnswersJsonEvenToABrowser(): void
    {
        // Its format is fixed by the specification, whatever `Accept` asks for.
        $response = $this->request('GET', '/oidc/userinfo', [
            'Accept' => 'text/html',
            'Authorization' => 'Bearer nope',
        ]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', self::json($response)['error']);
    }

    public function testANonceOutsideAnOpenIdRequestMeansNothing(): void
    {
        // Only an OpenID Connect request has a nonce; elsewhere it is an unknown parameter.
        $this->publicClient();
        $this->loggedIn();
        [, $challenge] = $this->makePkcePair();
        $params = $this->authorizeParams($challenge, ['scope' => 'profile', 'nonce' => 'repeated']);

        $this->extractCode($this->get('/oauth2/authorize', $params));
        $this->extractCode($this->get('/oauth2/authorize', $params));
    }

    public function testAMalformedNonceIsReportedToTheClient(): void
    {
        $this->publicClient();
        $this->loggedIn();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge, [
            'scope' => 'openid',
            'nonce' => str_repeat('n', 513),
        ]));

        self::assertSame(302, $response->getStatusCode());
        self::assertSame('invalid_request', self::locationQuery($response)['error']);
    }

    public function testAReplayedNonceIsRefusedBeforeAnyoneIsAskedToSignIn(): void
    {
        // Validation comes before login: a request already answered gets no login page.
        $this->publicClient();
        $this->loggedIn();
        [, $challenge] = $this->makePkcePair();
        $params = $this->authorizeParams($challenge, ['scope' => 'openid', 'nonce' => 'seen']);
        $this->extractCode($this->get('/oauth2/authorize', $params));

        $this->boot();
        $replayed = $this->get('/oauth2/authorize', $params);

        self::assertSame(302, $replayed->getStatusCode());
        self::assertStringStartsWith(self::TEST_REDIRECT_URI, $replayed->getHeaderLine('Location'));
        self::assertSame('invalid_request', self::locationQuery($replayed)['error']);
    }

    private function userinfo(mixed $accessToken): ResponseInterface
    {
        self::assertIsString($accessToken);

        return $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Bearer ' . $accessToken]);
    }

    /** @return list<string> */
    private function publishedKids(): array
    {
        $kids = [];
        foreach ($this->publishedKeySet()->all() as $key) {
            $kid = $key->get('kid');
            self::assertIsString($kid);
            $kids[] = $kid;
        }

        return $kids;
    }

    private function setProfile(Profile $profile): void
    {
        $users = $this->container()->get(UserRepository::class);
        $user = $users->findByEmail(self::TEST_USER_EMAIL);
        self::assertNotNull($user);

        $user->changeProfile($profile, new DateTimeImmutable());
        $users->save($user);
    }
}
