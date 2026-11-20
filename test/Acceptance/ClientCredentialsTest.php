<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Throwable;

/**
 * The Client Credentials grant (RFC 6749 §4.4), end to end — ported from the Python
 * suite's `test_client_credentials.py`.
 *
 * A machine authenticating as itself. There is no person to protect from the client,
 * so these tests are about the client proving it holds a secret, about its token being
 * no broader than its grant, and about that token never passing for one about a person.
 */
final class ClientCredentialsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;

    // ── The happy path ──────────────────────────────────────────────────────────

    public function testIssuesABearerTokenWithNoSubject(): void
    {
        $this->machineApi();

        $response = $this->requestMachineToken();

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $payload = self::json($response);
        self::assertSame('Bearer', $payload['token_type']);
        self::assertIsString($payload['access_token']);
        self::assertSame(3600, $payload['expires_in']);
        // RFC 6749 §4.4.3: no refresh token — a client that can authenticate once can do so again.
        self::assertArrayNotHasKey('refresh_token', $payload);
        // And no ID token: there is no end user for one to describe.
        self::assertArrayNotHasKey('id_token', $payload);

        // The missing subject is the point: nothing downstream can take this token for
        // one about a person.
        $stored = $this->onlyRow('oauth2_access_tokens');
        self::assertNull($stored['user_id']);
        self::assertNull($stored['authorization_code_id']);
        self::assertSame(self::TEST_M2M_CLIENT_ID, $stored['client_id']);
        self::assertSame(self::TEST_M2M_AUDIENCE, $stored['audience']);
    }

    public function testTokenIsStoredOnlyAsADigest(): void
    {
        $this->machineApi();

        $token = self::json($this->requestMachineToken())['access_token'];

        self::assertIsString($token);
        $stored = $this->onlyRow('oauth2_access_tokens');
        self::assertSame(Digest::of($token)->toString(), $stored['token_hash']);
        self::assertStringNotContainsString($token, (string) json_encode($stored));
    }

    public function testClientSecretPostIsAcceptedWhenRegisteredForIt(): void
    {
        $client = $this->m2mClient(ClientAuthMethod::ClientSecretPost);
        $this->grantClient($client, $this->anApi(self::TEST_M2M_AUDIENCE, ['api:read']), 'api:read');

        $response = $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::TEST_M2M_CLIENT_ID,
            'client_secret' => self::TEST_M2M_SECRET,
            'audience' => self::TEST_M2M_AUDIENCE,
        ]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    }

    public function testClientRegisteredForBasicCannotPostItsSecret(): void
    {
        $this->machineApi();

        $response = $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::TEST_M2M_CLIENT_ID,
            'client_secret' => self::TEST_M2M_SECRET,
            'audience' => self::TEST_M2M_AUDIENCE,
        ]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
    }

    // ── Client authentication ───────────────────────────────────────────────────

    public function testBasicCredentialsAreReadWhateverTheHeaderCase(): void
    {
        // Header names are case-insensitive (RFC 9110 §5.1).
        $this->machineApi();

        $response = $this->request(
            'POST',
            '/oauth2/token',
            [
                'AUTHORIZATION' => 'Basic ' . base64_encode(self::TEST_M2M_CLIENT_ID . ':' . self::TEST_M2M_SECRET),
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            body: http_build_query(['grant_type' => 'client_credentials', 'audience' => self::TEST_M2M_AUDIENCE]),
        );

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    }

    public function testWrongSecretIsRefused(): void
    {
        $this->machineApi();

        $response = $this->requestMachineToken(credentials: [self::TEST_M2M_CLIENT_ID, 'not-the-secret']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    public function testFailedAuthenticationCarriesAChallenge(): void
    {
        // A 401 says how to authenticate (RFC 9110 §11.6.1, RFC 6749 §5.2).
        $this->machineApi();

        $response = $this->requestMachineToken(credentials: [self::TEST_M2M_CLIENT_ID, 'not-the-secret']);

        self::assertSame(401, $response->getStatusCode());
        self::assertStringStartsWith('Basic realm=', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testUnknownClientIsRefused(): void
    {
        $response = $this->requestMachineToken(credentials: ['no-such-client', 'irrelevant']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
    }

    public function testPublicClientCannotUseThisGrant(): void
    {
        // RFC 6749 §4.4: confidential clients only. A public client has no secret, and its
        // client_id alone is public knowledge, so `none` is not accepted by this grant.
        $this->publicClient();

        $response = $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::TEST_CLIENT_ID,
            'audience' => self::TEST_M2M_AUDIENCE,
        ]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
    }

    public function testClientMarkedPublicButHoldingASecretIsRefused(): void
    {
        // Inconsistent registration data fails closed — here, before it can be stored at
        // all: the registration refuses it and so does the table.
        try {
            TestStorage::database()->execute(
                <<<'SQL'
                    INSERT INTO oauth2_clients (
                        client_id, client_secret_hash, name, client_type, grant_types, token_endpoint_auth_method
                    ) VALUES (
                        'mislabelled-client', '$2y$04$abcdefghijklmnopqrstuu', 'Public on paper', 'public',
                        '["client_credentials"]', 'client_secret_basic'
                    )
                    SQL,
            );
            self::fail('A public client holding a secret was stored.');
        } catch (Throwable $refused) {
            self::assertStringContainsString('ck_oauth2_clients_secret', self::messages($refused));
        }

        $response = $this->requestMachineToken(credentials: ['mislabelled-client', 'a-real-secret']);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testClientNotRegisteredForTheGrantIsRefused(): void
    {
        // Holding a valid secret is not the same as being allowed to use this grant.
        $this->confidentialClient();

        $response = $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
            'audience' => self::TEST_M2M_AUDIENCE,
        ]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('unauthorized_client', self::json($response)['error']);
    }

    // ── Scope ───────────────────────────────────────────────────────────────────

    public function testOmittedScopeGrantsTheWholeGrant(): void
    {
        // RFC 6749 §3.3's server-defined default. Unlike the code grant, where silence is
        // not consent, here the client grant is itself the authorization decision.
        $this->machineApi();

        self::assertSame(self::TEST_M2M_SCOPE, self::json($this->requestMachineToken())['scope']);
    }

    public function testNarrowerScopeIsHonoured(): void
    {
        $this->machineApi();

        self::assertSame('api:read', self::json($this->requestMachineToken(['scope' => 'api:read']))['scope']);
    }

    public function testScopeBeyondTheGrantIsRefused(): void
    {
        // Refused, not quietly narrowed: nobody watches a machine's token response.
        $this->machineApi();

        $response = $this->requestMachineToken(['scope' => 'api:read api:delete']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_scope', self::json($response)['error']);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    public function testScopeTheServerSupportsButTheGrantLacksIsRefused(): void
    {
        // The client grant is the authority, not the server-wide scope list.
        $this->machineApi();

        $response = $this->requestMachineToken(['scope' => 'profile']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_scope', self::json($response)['error']);
    }

    public function testOpenidScopeIsRefusedEvenWhenTheApiDefinesIt(): void
    {
        // `openid` asks for an ID token about an end user, and there is none.
        $client = $this->m2mClient();
        $this->grantClient($client, $this->anApi(self::TEST_M2M_AUDIENCE, ['openid', 'api:read']), 'openid api:read');

        $response = $this->requestMachineToken(['scope' => 'openid']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_scope', self::json($response)['error']);
    }

    // ── What a machine token is not ─────────────────────────────────────────────

    public function testMachineTokenIsRefusedByUserinfo(): void
    {
        // A token with no subject cannot answer a question about a subject.
        $this->machineApi();
        $token = self::json($this->requestMachineToken())['access_token'];
        self::assertIsString($token);

        $response = $this->request('GET', '/oidc/userinfo', ['Authorization' => 'Bearer ' . $token]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', self::json($response)['error']);
    }

    public function testMachineClientCannotStartAnInteractiveFlow(): void
    {
        // Registered with no redirect URI: it fails at the first check rather than
        // half-working, and there is nowhere to send an error back to.
        $this->m2mClient();

        $response = $this->get(
            '/oauth2/authorize',
            ['response_type' => 'code', 'client_id' => self::TEST_M2M_CLIENT_ID],
        );

        self::assertSame(400, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Location'));
    }

    public function testDiscoveryAdvertisesTheGrant(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame(
            ['authorization_code', 'client_credentials', 'refresh_token'],
            $document['grant_types_supported'],
        );
    }

    // ── The audience (beyond the Python suite, which covers it in test_audience) ──

    public function testTheAudienceIsRequired(): void
    {
        $this->machineApi();

        $response = $this->requestMachineToken(['audience' => null]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_request', self::json($response)['error']);
    }

    public function testAnUnknownAudienceIsAnInvalidTarget(): void
    {
        // RFC 8707 §2.
        $this->machineApi();

        $response = $this->requestMachineToken(['audience' => 'https://nowhere.test/api/']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_target', self::json($response)['error']);
    }

    public function testAnApiTheClientHoldsNoGrantOnIsDenied(): void
    {
        $this->machineApi();
        $this->anApi('https://other.test/api/', ['other:read']);

        $response = $this->requestMachineToken(['audience' => 'https://other.test/api/']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('access_denied', self::json($response)['error']);
    }

    public function testAPermissionWithdrawnFromTheApiIsNoLongerIssued(): void
    {
        // The grant is intersected with what the API defines now, not trusted.
        $this->machineApi();
        $this->anApi(self::TEST_M2M_AUDIENCE, ['api:read']);

        self::assertSame('api:read', self::json($this->requestMachineToken())['scope']);
        self::assertSame(400, $this->requestMachineToken(['scope' => 'api:write'])->getStatusCode());
    }

    private static function messages(Throwable $error): string
    {
        $messages = [];
        for ($current = $error; $current !== null; $current = $current->getPrevious()) {
            $messages[] = $current->getMessage();
        }

        return implode(' | ', $messages);
    }
}
