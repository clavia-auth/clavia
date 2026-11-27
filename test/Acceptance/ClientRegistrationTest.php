<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\RevokeInitialAccessToken;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Digest;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\ResponseInterface;

/**
 * Dynamic client registration (RFC 7591; docs/design/dynamic-client-registration.md, slice 2):
 * open only to a bearer of an operator's initial access token, and a client registered this way
 * is third-party, so it never reaches a system API.
 */
final class ClientRegistrationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string ON = 'token';
    private const array WEB_APP = [
        'client_name' => 'Acme Reports',
        'redirect_uris' => ['https://reports.acme.example/callback'],
    ];

    // ── Switched off ────────────────────────────────────────────────────────────

    public function testOffThereIsNoEndpointAndDiscoveryNamesNone(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'off']);

        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->registerItself(self::WEB_APP, 'any')->getStatusCode(),
        );
        $discovery = self::json($this->get('/.well-known/openid-configuration'));
        self::assertArrayNotHasKey('registration_endpoint', $discovery);
    }

    public function testOnDiscoveryNamesTheEndpoint(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);

        self::assertSame(
            'https://auth.clavia.test/oauth2/register',
            self::json($this->get('/.well-known/oauth-authorization-server'))['registration_endpoint'] ?? null,
        );
    }

    // ── The initial access token ────────────────────────────────────────────────

    public function testWithoutATokenTheAnswerIsABareChallenge(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);

        $response = $this->registerItself(self::WEB_APP, null);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('Bearer realm="https://auth.clavia.test"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAnUnknownExpiredRevokedOrUsedUpTokenIsOneAnswer(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);
        $clock = $this->freezeClock();
        $expiring = $this->initialAccessToken(lifetime: 60);
        $revoked = $this->initialAccessToken();
        $this->container()->get(RevokeInitialAccessToken::class)($this->idOf($revoked));
        $usedUp = $this->initialAccessToken();
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $this->registerItself(self::WEB_APP, $usedUp)->getStatusCode(),
        );
        $clock->advance(60);

        $tokens = ['unknown' => 'not-a-token', 'expired' => $expiring, 'revoked' => $revoked, 'used up' => $usedUp];
        foreach ($tokens as $case => $token) {
            $response = $this->registerItself(self::WEB_APP, $token);

            self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode(), $case);
            self::assertSame('invalid_token', self::json($response)['error'], $case);
        }
    }

    public function testARefusedRegistrationSpendsNoUse(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);
        $token = $this->initialAccessToken();

        $refused = $this->registerItself(['client_name' => 'No redirect'], $token);
        $accepted = $this->registerItself(self::WEB_APP, $token);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $accepted->getStatusCode(),
            (string) $accepted->getBody(),
        );
    }

    // ── Registering ─────────────────────────────────────────────────────────────

    public function testAConfidentialClientIsRegisteredAsAThirdPartyOne(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);
        $this->freezeClock('2026-01-15T10:00:00Z');
        $token = $this->initialAccessToken();

        $response = $this->registerItself(self::WEB_APP + [
            'post_logout_redirect_uris' => ['https://reports.acme.example/bye'],
            'require_pkce' => false,
            'mfa_policy' => 'required',
            'logo_uri' => 'https://acme.example/logo.png',
            'claims' => [['name' => 'plan', 'source' => 'app_metadata.plan', 'in' => ['id_token']]],
            // Operators only (#219): this server would send people to it.
            'initiate_login_uri' => 'https://reports.acme.example/sign-in',
        ], $token);

        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $document = self::json($response);
        self::assertIsString($document['client_id']);
        self::assertStringStartsWith(ClientId::THIRD_PARTY_PREFIX, $document['client_id']);
        self::assertIsString($document['client_secret']);
        self::assertSame(0, $document['client_secret_expires_at']);
        self::assertSame(1768471200, $document['client_id_issued_at']);
        self::assertIsString($document['registration_access_token']);
        self::assertSame(
            'https://auth.clavia.test/oauth2/register/' . $document['client_id'],
            $document['registration_client_uri'],
        );
        self::assertSame('client_secret_basic', $document['token_endpoint_auth_method']);
        self::assertSame(['authorization_code'], $document['grant_types']);
        self::assertSame(['code'], $document['response_types']);
        self::assertSame(['https://reports.acme.example/callback'], $document['redirect_uris']);
        self::assertSame(['https://reports.acme.example/bye'], $document['post_logout_redirect_uris']);
        self::assertFalse($document['dpop_bound_access_tokens']);
        // Ignored, and so not in the answer (RFC 7591 §3.2.1).
        foreach (['require_pkce', 'mfa_policy', 'logo_uri', 'claims', 'initiate_login_uri'] as $ignored) {
            self::assertArrayNotHasKey($ignored, $document);
        }

        $client = $this->container()->get(ClientRepository::class)->find(ClientId::fromString($document['client_id']));
        self::assertNotNull($client);
        self::assertSame(Ownership::ThirdParty, $client->id->ownership());
        self::assertTrue($client->requiresPkce, 'PKCE stays required.');
        self::assertSame([], $client->connections);
        self::assertTrue($client->claims->isEmpty(), 'A self-registered client never sets its custom claims.');
        self::assertNull($client->initiateLoginUri, 'Nor where people are sent to start again.');
        $registration = $this->container()->get(ClientRegistrationRepository::class)->find($client->id);
        self::assertTrue($registration?->accessTokenDigest->equals(Digest::of($document['registration_access_token'])));
        self::assertTrue($registration?->initialAccessTokenId?->equals($this->idOf($token)));
    }

    public function testTheRegistrationIsAuditedAsTheClientActingAsItself(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);
        $token = $this->initialAccessToken();

        $clientId = self::json($this->registerItself(self::WEB_APP, $token))['client_id'];
        self::assertIsString($clientId);

        $row = TestStorage::database()->fetchOne(
            'SELECT actor_kind, actor_client_id, details::text AS detail FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::ClientCreated->value],
        );
        self::assertSame('application', $row['actor_kind'] ?? null);
        self::assertSame($clientId, $row['actor_client_id'] ?? null);
        self::assertNotNull($row);
        self::assertIsString($row['detail']);
        self::assertStringContainsString($this->idOf($token)->value, $row['detail']);
        $trail = TestStorage::database()->fetchAll('SELECT * FROM audit_events');
        self::assertStringNotContainsString($token, (string) json_encode($trail));
    }

    public function testAPublicNativeClientMayUseALoopbackRedirect(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);

        $response = $this->registerItself([
            'client_name' => 'Acme CLI',
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'redirect_uris' => ['http://127.0.0.1:8400/callback', 'http://[::1]:8400/callback'],
        ], $this->initialAccessToken());

        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertArrayNotHasKey('client_secret', self::json($response));
    }

    public function testARegisteredClientAsksThePersonForConsent(): void
    {
        $this->boot([
            'CLAVIA_CLIENT_REGISTRATION' => self::ON,
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
        ]);
        $this->user();
        $clientId = self::json($this->registerItself(self::WEB_APP, $this->initialAccessToken()))['client_id'];
        self::assertIsString($clientId);

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], [
            'client_id' => $clientId,
            'redirect_uri' => 'https://reports.acme.example/callback',
        ]));

        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $response->getStatusCode());
        self::assertStringStartsWith('/auth/consent', $response->getHeaderLine('Location'));
    }

    public function testARegisteredClientNeverReachesTheManagementApi(): void
    {
        $this->boot([
            'CLAVIA_CLIENT_REGISTRATION' => self::ON,
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
        ]);
        $this->user();
        $this->managementApi();
        $web = self::json($this->registerItself(self::WEB_APP, $this->initialAccessToken()));
        self::assertIsString($web['client_id']);

        $authorize = $this->get('/oauth2/authorize', $this->authorizeParams($this->makePkcePair()[1], [
            'client_id' => $web['client_id'],
            'redirect_uri' => 'https://reports.acme.example/callback',
            'audience' => self::MANAGEMENT_API,
            'scope' => 'read:users',
        ]));
        $machine = $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'audience' => self::MANAGEMENT_API,
        ], basicAuth: [$web['client_id'], (string) $web['client_secret']]);

        self::assertSame('access_denied', self::locationQuery($authorize)['error'] ?? null);
        self::assertSame('unauthorized_client', self::json($machine)['error'], 'It holds no client_credentials grant.');
    }

    // ── Refusals ────────────────────────────────────────────────────────────────

    /**
     * @param array<string, mixed> $metadata
     */
    #[DataProvider('refusals')]
    public function testWhatASelfRegisteredClientMayNotHaveIsRefused(array $metadata, string $error): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);

        $response = $this->registerItself($metadata, $this->initialAccessToken());

        self::assertSame(
            StatusCodeInterface::STATUS_BAD_REQUEST,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame($error, self::json($response)['error']);
        self::assertSame(0, (int) TestStorage::database()->fetchValue('SELECT count(*) FROM client_registrations'));
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function refusals(): iterable
    {
        $app = self::WEB_APP;
        yield 'no client_name' => [['redirect_uris' => $app['redirect_uris']], 'invalid_client_metadata'];
        yield 'a client_name too long' => [['client_name' => str_repeat('a', 121)] + $app, 'invalid_client_metadata'];
        yield 'no redirect URI for the code flow' => [['client_name' => 'x'], 'invalid_redirect_uri'];
        yield 'http on a public host' => [
            ['redirect_uris' => ['http://acme.example/cb']] + $app,
            'invalid_redirect_uri',
        ];
        yield 'localhost by name' => [[
            'redirect_uris' => ['http://localhost:8400/cb'],
            'token_endpoint_auth_method' => 'none',
        ] + $app, 'invalid_redirect_uri'];
        yield 'loopback for a confidential client' => [
            ['redirect_uris' => ['http://127.0.0.1/cb']] + $app,
            'invalid_redirect_uri',
        ];
        yield 'a fragment' => [['redirect_uris' => ['https://acme.example/cb#x']] + $app, 'invalid_redirect_uri'];
        yield 'a custom scheme' => [['redirect_uris' => ['com.acme.app://cb']] + $app, 'invalid_redirect_uri'];
        yield 'a post-logout URI over http' => [
            ['post_logout_redirect_uris' => ['http://acme.example/bye']] + $app,
            'invalid_redirect_uri',
        ];
        yield 'client credentials' => [['grant_types' => ['client_credentials']] + $app, 'invalid_client_metadata'];
        yield 'an implicit response' => [['response_types' => ['token']] + $app, 'invalid_client_metadata'];
        yield 'the device flow' => [[
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'token_endpoint_auth_method' => 'none',
        ] + $app, 'invalid_client_metadata'];
        yield 'code without its grant' => [[
            'grant_types' => ['refresh_token'],
            'response_types' => ['code'],
        ] + $app, 'invalid_client_metadata'];
        yield 'a refresh token alone' => [
            ['grant_types' => ['refresh_token'], 'response_types' => []] + $app,
            'invalid_client_metadata',
        ];
        yield 'private_key_jwt' => [
            ['token_endpoint_auth_method' => 'private_key_jwt'] + $app,
            'invalid_client_metadata',
        ];
        yield 'a number for a name' => [['client_name' => 42] + $app, 'invalid_client_metadata'];
        yield 'a string for a list' => [
            ['client_name' => 'x', 'redirect_uris' => 'https://acme.example/cb'],
            'invalid_client_metadata',
        ];
        yield 'a private back-channel URI' => [
            ['backchannel_logout_uri' => 'https://10.0.0.1/logout'] + $app,
            'invalid_client_metadata',
        ];
        yield 'a software statement' => [['software_statement' => 'eyJ.eyJ.sig'] + $app, 'invalid_software_statement'];
    }

    public function testABodyThatIsNotAJsonObjectIsRefused(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON]);
        $token = $this->initialAccessToken();

        foreach (['[1, 2]', '{"client_name": ', 'client_name=x'] as $body) {
            $response = $this->request(RequestMethodInterface::METHOD_POST, '/oauth2/register', [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json',
            ], body: $body);

            self::assertSame('invalid_client_metadata', self::json($response)['error'], $body);
        }
    }

    public function testRegistrationsFromOneAddressAreLimited(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => self::ON, 'CLAVIA_CLIENT_REGISTRATION_MAX_PER_ADDRESS' => '2']);

        $this->registerItself(self::WEB_APP, 'guess-1');
        $this->registerItself(self::WEB_APP, 'guess-2');
        $third = $this->registerItself(self::WEB_APP, $this->initialAccessToken());

        self::assertSame(StatusCodeInterface::STATUS_TOO_MANY_REQUESTS, $third->getStatusCode());
        self::assertSame('3600', $third->getHeaderLine('Retry-After'));
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function registerItself(array $metadata, ?string $token): ResponseInterface
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($token !== null) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        return $this->request(
            RequestMethodInterface::METHOD_POST,
            '/oauth2/register',
            $headers,
            body: (string) json_encode($metadata),
        );
    }

    /** @return non-empty-string */
    private function initialAccessToken(int $lifetime = 3600): string
    {
        return $this->container()->get(IssueInitialAccessToken::class)(
            new NewInitialAccessToken('Acme', $lifetime, 1),
        )->secret;
    }

    private function idOf(string $token): \Clavia\Domain\Client\Registration\InitialAccessTokenId
    {
        $found = $this->container()->get(\Clavia\Domain\Client\Registration\InitialAccessTokenRepository::class)
            ->findByDigest(Digest::of($token));
        self::assertNotNull($found);

        return $found->id;
    }
}
