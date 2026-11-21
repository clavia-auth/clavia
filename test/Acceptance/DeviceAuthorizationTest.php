<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * The device authorization grant (RFC 8628) — ported from the Python suite's
 * `test_device_authorization.py`.
 *
 * A device with no browser asks for a code, a person types it on a machine that has one,
 * and the device polls until the person has decided. What matters: a device code is
 * redeemed once and only by the client it was issued to; polling is held to the
 * interval the way the RFC says; the person sees what is asked and can refuse; and the
 * token that comes out is narrowed to their roles like every other.
 */
final class DeviceAuthorizationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;
    use OidcFixtures;

    private const string DEVICE_CLIENT_ID = 'test-device-client';
    private const string GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
    private const string INVOICES = 'https://invoices.test/api/';

    private ?FrozenClock $clock = null;

    // ── Asking for a code ───────────────────────────────────────────────────────

    public function testADeviceGetsACodeToPollWithAndACodeToShow(): void
    {
        $this->deviceClient();

        $response = $this->requestCode();

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = self::json($response);
        self::assertIsString($body['device_code']);
        self::assertGreaterThanOrEqual(40, strlen($body['device_code']));
        self::assertIsString($body['user_code']);
        self::assertMatchesRegularExpression('/^[B-Z]{4}-[B-Z]{4}$/D', $body['user_code']);
        self::assertSame('https://auth.clavia.test/auth/device', $body['verification_uri']);
        self::assertSame(
            'https://auth.clavia.test/auth/device?user_code=' . $body['user_code'],
            $body['verification_uri_complete'],
        );
        self::assertSame(600, $body['expires_in']);
        self::assertSame(5, $body['interval']);
    }

    public function testAClientNotRegisteredForTheGrantIsRefused(): void
    {
        $this->publicClient();

        $response = $this->post('/oauth2/device/code', ['client_id' => self::TEST_CLIENT_ID, 'scope' => 'openid']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('unauthorized_client', self::json($response)['error']);
    }

    public function testAnUnknownClientIsRefused(): void
    {
        $response = $this->post('/oauth2/device/code', ['client_id' => 'nobody', 'scope' => 'openid']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
    }

    public function testTheScopeIsCheckedAgainstTheAudience(): void
    {
        $this->machineApi();
        $this->deviceClient();

        $refused = $this->requestCode('openid api:delete', self::TEST_M2M_AUDIENCE);
        self::assertSame(400, $refused->getStatusCode());
        self::assertSame('invalid_scope', self::json($refused)['error']);

        self::assertSame(
            'invalid_target',
            self::json($this->requestCode('openid', 'https://nothing.test/'))['error'],
        );
        self::assertSame(200, $this->requestCode('openid api:read', self::TEST_M2M_AUDIENCE)->getStatusCode());
    }

    public function testThirdPartyApplicationsCannotRegisterForTheGrant(): void
    {
        $this->adminToken();

        $refused = $this->api('POST', '/api/v1/clients', [
            'client_type' => 'public',
            'grant_types' => [self::GRANT],
            'is_first_party' => false,
        ]);
        self::assertSame(422, $refused->getStatusCode());

        $allowed = $this->api('POST', '/api/v1/clients', [
            'client_type' => 'public',
            'grant_types' => [self::GRANT, 'refresh_token'],
        ]);
        self::assertSame(201, $allowed->getStatusCode(), (string) $allowed->getBody());
    }

    // ── Polling ─────────────────────────────────────────────────────────────────

    public function testPollingBeforeTheDecisionIsPending(): void
    {
        $this->deviceClient();
        $codes = $this->codes();

        $response = $this->poll($codes['device_code']);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('authorization_pending', self::json($response)['error']);
    }

    public function testPollingTooFastEarnsSlowDownAndALongerInterval(): void
    {
        $this->deviceClient();
        $codes = $this->codes();

        $this->poll($codes['device_code']);
        $hurried = $this->poll($codes['device_code']);

        self::assertSame('slow_down', self::json($hurried)['error']);
        self::assertStringContainsString('wait 10 seconds', (string) self::json($hurried)['error_description']);
        $this->clock()->advance(9);
        self::assertSame('slow_down', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testPollingByAnotherClientIsRefused(): void
    {
        $this->deviceClient();
        $this->m2mClient();
        $codes = $this->codes();

        $response = $this->post(
            '/oauth2/token',
            ['grant_type' => self::GRANT, 'device_code' => $codes['device_code']],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        );

        self::assertSame('unauthorized_client', self::json($response)['error']);
    }

    public function testAnotherDeviceClientCannotRedeemTheCode(): void
    {
        $this->deviceClient();
        $this->deviceClient('another-device');
        $codes = $this->codes();

        self::assertSame('invalid_grant', self::json($this->poll($codes['device_code'], 'another-device'))['error']);
        self::assertSame('authorization_pending', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testAnUnknownDeviceCodeIsInvalidGrant(): void
    {
        $this->deviceClient();

        $response = $this->poll('never-issued');

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testAnExpiredCodeSaysSo(): void
    {
        $this->deviceClient();
        $codes = $this->codes();
        $this->clock()->advance(600);

        self::assertSame('expired_token', self::json($this->poll($codes['device_code']))['error']);
    }

    // ── The person's side ───────────────────────────────────────────────────────

    public function testThePageNeedsASignedInPerson(): void
    {
        $response = $this->get('/auth/device', ['user_code' => 'BCDF-GHJK']);

        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?state=', $response->getHeaderLine('Location'));
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);
        self::assertSame('/auth/device?user_code=BCDF-GHJK', $this->loginState($state)?->nextUrl);
    }

    public function testWithoutACodeThePageAsksForOne(): void
    {
        $this->loggedIn();

        $page = $this->get('/auth/device');

        self::assertSame(200, $page->getStatusCode());
        self::assertStringContainsString('name="user_code"', (string) $page->getBody());
    }

    public function testAWrongCodeIsRefusedOnThePage(): void
    {
        $this->loggedIn();

        foreach (['ZZZZ-ZZZZ', 'not a code'] as $typed) {
            $page = $this->get('/auth/device', ['user_code' => $typed]);

            self::assertSame(400, $page->getStatusCode());
            self::assertStringContainsString('not valid or has expired', (string) $page->getBody());
        }
    }

    public function testGuessingCodesIsCutShortAndTheRightOneThenWaits(): void
    {
        // RFC 8628 §5.1: user code entry is rate-limited, as wrong passwords are.
        $this->boot(['CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL, 'CLAVIA_LOGIN_MAX_ATTEMPTS' => '3']);
        $this->user();
        $this->deviceClient();
        $codes = $this->codes();

        foreach (['BCDF-GHJK', 'BCDF-GHJL', 'BCDF-GHJM'] as $guess) {
            self::assertSame(400, $this->get('/auth/device', ['user_code' => $guess])->getStatusCode());
        }
        $page = $this->get('/auth/device', ['user_code' => $codes['user_code']]);

        self::assertSame(429, $page->getStatusCode());
        self::assertStringContainsString('Too many codes were not valid', (string) $page->getBody());
        self::assertStringNotContainsString('Living-room TV', (string) $page->getBody(), 'Nothing is looked up.');
    }

    public function testThePageShowsWhoIsAskingAndForWhat(): void
    {
        $this->loggedIn();
        $this->machineApi();
        $this->deviceClient();
        $codes = $this->codes('openid api:read', self::TEST_M2M_AUDIENCE);

        $page = $this->get('/auth/device', ['user_code' => $codes['user_code']]);

        self::assertSame(200, $page->getStatusCode());
        $body = html_entity_decode((string) $page->getBody());
        self::assertStringContainsString('Living-room TV', $body);
        self::assertStringContainsString('Sign you in and know who you are', $body);
        self::assertStringContainsString('api:read', $body);
        self::assertStringContainsString(self::TEST_USER_EMAIL, $body);
        self::assertStringNotContainsString('<script', $body);
    }

    public function testTypedCodesAreForgiving(): void
    {
        // Lower case, no dash, stray spaces: the same code.
        $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes();
        $typed = strtolower(str_replace('-', ' ', $codes['user_code']));

        $page = $this->get('/auth/device', ['user_code' => $typed]);

        self::assertSame(200, $page->getStatusCode());
        self::assertStringContainsString('Living-room TV', (string) $page->getBody());
    }

    public function testApprovalLetsTheDeviceRedeemTheCodeOnce(): void
    {
        $user = $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes('openid profile');

        $done = $this->approve($codes['user_code']);
        self::assertSame(200, $done->getStatusCode());
        self::assertStringContainsString('Device connected', (string) $done->getBody());

        $token = $this->poll($codes['device_code']);
        self::assertSame(200, $token->getStatusCode(), (string) $token->getBody());
        $body = self::json($token);
        self::assertIsString($body['access_token']);
        self::assertIsString($body['refresh_token'], 'Registered for refresh tokens.');
        self::assertEqualsCanonicalizing(['openid', 'profile'], explode(' ', (string) $body['scope']));
        $stored = $this->onlyRow('oauth2_access_tokens');
        self::assertSame($user->id->value, $stored['user_id']);
        self::assertSame(self::DEVICE_CLIENT_ID, $stored['client_id']);
        self::assertNull($stored['authorization_code_id']);
        // An ID token the published keys verify, for the person, naming the device client.
        $claims = $this->verifiedIdToken($body['id_token'] ?? null)['claims'];
        self::assertSame($user->id->value, $claims['sub']);
        self::assertSame(self::DEVICE_CLIENT_ID, $claims['aud']);
        self::assertArrayNotHasKey('nonce', $claims);

        // Redeemed once: the code is gone.
        self::assertSame('invalid_grant', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testTheDevicesRefreshTokenRefreshes(): void
    {
        $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes();
        $this->approve($codes['user_code']);
        $refreshToken = self::json($this->poll($codes['device_code']))['refresh_token'] ?? null;
        self::assertIsString($refreshToken);

        $refreshed = $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::DEVICE_CLIENT_ID,
            'refresh_token' => $refreshToken,
        ]);

        self::assertSame(200, $refreshed->getStatusCode(), (string) $refreshed->getBody());
    }

    public function testRefusalReachesTheDevice(): void
    {
        $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes();

        $done = $this->approve($codes['user_code'], 'deny');

        self::assertStringContainsString('Device refused', (string) $done->getBody());
        self::assertSame('access_denied', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testApprovalIsRecordedAsAConsent(): void
    {
        $user = $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes('openid email');

        $this->approve($codes['user_code']);

        $consent = $this->container()->get(ConsentRepository::class)
            ->find($user->id, ClientId::fromString(self::DEVICE_CLIENT_ID), null);
        self::assertNotNull($consent);
        self::assertEqualsCanonicalizing(['openid', 'email'], $consent->scope->toList());
    }

    public function testACodeCannotBeDecidedTwice(): void
    {
        $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes();
        $this->approve($codes['user_code']);

        self::assertSame(400, $this->get('/auth/device', ['user_code' => $codes['user_code']])->getStatusCode());
        self::assertStringContainsString(
            'not valid or has expired',
            (string) $this->decide($codes['user_code'], 'deny')->getBody(),
        );
        self::assertSame(200, $this->poll($codes['device_code'])->getStatusCode(), 'Still approved.');
    }

    public function testAFormWithoutItsCsrfTokenDecidesNothing(): void
    {
        $this->loggedIn();
        $this->deviceClient();
        $codes = $this->codes();

        $response = $this->post('/auth/device', [
            'user_code' => $codes['user_code'],
            'decision' => 'allow',
            'csrf_token' => 'forged',
        ]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('authorization_pending', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testTheTokenIsNarrowedToThePersonsRoles(): void
    {
        $user = $this->loggedIn();
        $this->invoicesApi();
        $reader = $this->container()->get(EnsureRole::class)(
            'Reader',
            '',
            Audience::fromString(self::INVOICES),
            ScopeSet::fromString('invoices:read'),
        );
        $this->container()->get(RoleRepository::class)->assign($reader->id, $user->id, new DateTimeImmutable());
        $this->deviceClient();
        $codes = $this->codes('openid invoices:read invoices:write', self::INVOICES);

        $this->approve($codes['user_code']);
        $token = self::json($this->poll($codes['device_code']));

        self::assertEqualsCanonicalizing(['openid', 'invoices:read'], explode(' ', (string) $token['scope']));
    }

    public function testAPersonWithNoRoleOnAnEnforcingApiCannotApprove(): void
    {
        $this->loggedIn();
        $this->invoicesApi();
        $this->deviceClient();
        $codes = $this->codes('openid invoices:read', self::INVOICES);

        $done = $this->approve($codes['user_code']);

        self::assertStringContainsString('do not have permission', (string) $done->getBody());
        self::assertSame('access_denied', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testApprovalThroughAConnectionTheApplicationDoesNotEnableIsNotAccepted(): void
    {
        // Signed in with a password; the device's application allows Google only.
        $this->user();
        self::assertSame(303, $this->submitLogin()->getStatusCode());
        $this->deviceClient(connections: ['google']);
        $codes = $this->codes();

        $page = $this->get('/auth/device', ['user_code' => $codes['user_code']]);
        self::assertSame(200, $page->getStatusCode());
        $response = $this->post('/auth/device', [
            'csrf_token' => self::csrfTokenFrom($page),
            'user_code' => $codes['user_code'],
            'decision' => 'allow',
        ]);

        self::assertSame(303, $response->getStatusCode());
        self::assertStringStartsWith('/auth/login?state=', $response->getHeaderLine('Location'));
        $state = self::locationQuery($response)['state'] ?? null;
        self::assertIsString($state);
        // The login page will offer the application's connections, and come back to the code.
        self::assertSame(self::DEVICE_CLIENT_ID, $this->loginState($state)?->clientId?->value);
        self::assertSame('authorization_pending', self::json($this->poll($codes['device_code']))['error']);
    }

    public function testDiscoveryAdvertisesTheGrant(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame('https://auth.clavia.test/oauth2/device/code', $document['device_authorization_endpoint']);
        self::assertIsArray($document['grant_types_supported']);
        self::assertContains(self::GRANT, $document['grant_types_supported']);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /**
     * The device client — public, no redirect URI, the device and refresh grants — enabling
     * the built-in connections unless told which.
     *
     * @param list<string>|null $connections
     */
    private function deviceClient(string $id = self::DEVICE_CLIENT_ID, ?array $connections = null): Client
    {
        $client = Client::register(
            ClientId::fromString($id),
            'Living-room TV',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [],
            [GrantType::DeviceCode, GrantType::RefreshToken],
            [],
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
            [],
            $connections === null
                ? Clients::builtInConnections($id)
                : array_map(ConnectionName::fromString(...), $connections),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    private function invoicesApi(): void
    {
        $api = $this->anApi(self::INVOICES, ['invoices:read', 'invoices:write'])->enforcingPolicies(true);
        $this->container()->get(ResourceServerRepository::class)->save($api);
    }

    private function requestCode(string $scope = 'openid profile', ?string $audience = null): ResponseInterface
    {
        $this->clock();
        $form = ['client_id' => self::DEVICE_CLIENT_ID, 'scope' => $scope];
        if ($audience !== null) {
            $form['audience'] = $audience;
        }

        return $this->post('/oauth2/device/code', $form);
    }

    /** @return array{device_code: string, user_code: string} */
    private function codes(string $scope = 'openid profile', ?string $audience = null): array
    {
        $response = $this->requestCode($scope, $audience);
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $body = self::json($response);
        $deviceCode = $body['device_code'] ?? null;
        $userCode = $body['user_code'] ?? null;
        self::assertIsString($deviceCode);
        self::assertIsString($userCode);

        return ['device_code' => $deviceCode, 'user_code' => $userCode];
    }

    private function poll(string $deviceCode, string $clientId = self::DEVICE_CLIENT_ID): ResponseInterface
    {
        return $this->post('/oauth2/token', [
            'grant_type' => self::GRANT,
            'device_code' => $deviceCode,
            'client_id' => $clientId,
        ]);
    }

    /** A signed-in person opens the device link and presses Allow — or Don't allow. */
    private function approve(string $userCode, string $decision = 'allow'): ResponseInterface
    {
        $page = $this->get('/auth/device', ['user_code' => $userCode]);
        self::assertSame(200, $page->getStatusCode(), (string) $page->getBody());

        return $this->post('/auth/device', [
            'csrf_token' => self::csrfTokenFrom($page),
            'user_code' => $userCode,
            'decision' => $decision,
        ]);
    }

    /** Post a decision with a valid CSRF token taken from the entry page. */
    private function decide(string $userCode, string $decision): ResponseInterface
    {
        $page = $this->get('/auth/device');

        return $this->post('/auth/device', [
            'csrf_token' => self::csrfTokenFrom($page),
            'user_code' => $userCode,
            'decision' => $decision,
        ]);
    }

    /**
     * The application's clock, stopped at the real time — so polls can be spaced without
     * sleeping, and Redis, which expires entries on its own clock, agrees with it.
     */
    private function clock(): FrozenClock
    {
        return $this->clock ??= $this->freezeClock(gmdate('Y-m-d\TH:i:s\Z'));
    }
}
