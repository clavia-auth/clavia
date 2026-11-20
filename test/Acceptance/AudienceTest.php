<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;

/**
 * Audiences: which API a token is for — ported from the Python suite's
 * `test_audience.py`, with the redemption-time checks this implementation adds.
 *
 * Registering an API is what makes a scope mean something, and `aud` is what ties a
 * token to one. The client credentials grant reads the client's grant on the API; the
 * authorization code grant reads the API's permissions, now at the authorization
 * endpoint and again when the code is redeemed.
 */
final class AudienceTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;

    private const string INVOICES_API = 'https://invoices.test/api/';

    // ── Client credentials ─────────────────────────────────────────────────────

    public function testAudienceBindsAMachineTokenToOneApi(): void
    {
        $this->grantClient($this->m2mClient(), $this->invoicesApi(), 'invoices:read');

        $response = $this->requestMachineToken(['audience' => self::INVOICES_API]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('invoices:read', self::json($response)['scope']);
        self::assertSame(self::INVOICES_API, $this->onlyRow('oauth2_access_tokens')['audience']);
    }

    public function testUnknownAudienceIsInvalidTarget(): void
    {
        $this->m2mClient();

        $response = $this->requestMachineToken(['audience' => 'https://nothing.test/']);

        self::assertSame(400, $response->getStatusCode());
        // RFC 8707 §2's code for a target the server cannot issue for.
        self::assertSame('invalid_target', self::json($response)['error']);
    }

    public function testClientWithoutAGrantIsRefused(): void
    {
        // The API exists; this client has no grant on it. A different error from an
        // unknown audience on purpose: different problems, different fixes.
        $this->m2mClient();
        $this->invoicesApi();

        $response = $this->requestMachineToken(['audience' => self::INVOICES_API]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('access_denied', self::json($response)['error']);
    }

    public function testTheGrantOnThatApiIsTheOnlyAuthority(): void
    {
        // The client holds `api:read` on the machine API; asking for it against the
        // invoices API, where it holds only `invoices:read`, must fail.
        $this->machineApi();
        $this->grantClient($this->m2mClientOnly(), $this->invoicesApi(), 'invoices:read');

        $response = $this->requestMachineToken(['scope' => 'api:read', 'audience' => self::INVOICES_API]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_scope', self::json($response)['error']);
    }

    public function testPermissionDroppedFromTheApiStopsBeingGrantable(): void
    {
        // The grant is intersected with the API's permissions, not merely trusted:
        // removing one takes effect on the next token.
        $api = $this->invoicesApi();
        $this->grantClient($this->m2mClient(), $api, 'invoices:read invoices:write');
        $this->dropWritePermission($api);

        self::assertSame(
            'invoices:read',
            self::json($this->requestMachineToken(['audience' => self::INVOICES_API]))['scope'],
        );
        $refused = $this->requestMachineToken(['scope' => 'invoices:write', 'audience' => self::INVOICES_API]);
        self::assertSame(400, $refused->getStatusCode());
        self::assertSame('invalid_scope', self::json($refused)['error']);
    }

    public function testGrantingAnUndefinedPermissionIsRefusedAtTheGrant(): void
    {
        // A typo in a provisioning command fails at the command, not months later.
        $client = $this->m2mClient();

        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessage('does not define: invoices:delete');

        ClientGrant::grant(
            $client->id,
            $this->invoicesApi(),
            ScopeSet::fromString('invoices:delete'),
            new DateTimeImmutable(),
        );
    }

    public function testAudienceIsRequired(): void
    {
        // A machine client holds nothing except through an API, so it must name one;
        // a token for no API could open no door, and would fail later, elsewhere.
        $this->machineApi();

        $response = $this->requestMachineToken(['audience' => null]);

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_request', self::json($response)['error']);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    public function testRegrantingReplacesRatherThanAccumulates(): void
    {
        $client = $this->m2mClient();
        $api = $this->invoicesApi();
        $this->grantClient($client, $api, 'invoices:read invoices:write');
        $this->grantClient($client, $api, 'invoices:read');

        self::assertSame(
            'invoices:read',
            self::json($this->requestMachineToken(['audience' => self::INVOICES_API]))['scope'],
        );
    }

    // ── Authorization code ─────────────────────────────────────────────────────

    public function testUserFlowCarriesTheAudienceOntoTheToken(): void
    {
        // A user-facing client asks for API permissions alongside OIDC scopes.
        $user = $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi();
        [$verifier, $challenge] = $this->makePkcePair();

        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid invoices:read', 'audience' => self::INVOICES_API],
        );
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read'],
            explode(' ', (string) self::json($response)['scope']),
        );
        $stored = $this->onlyRow('oauth2_access_tokens');
        self::assertSame(self::INVOICES_API, $stored['audience']);
        self::assertSame($user->id->value, $stored['user_id']);
    }

    public function testUserFlowRefusesAPermissionTheApiDoesNotDefine(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams(
            $challenge,
            ['scope' => 'openid invoices:delete', 'audience' => self::INVOICES_API],
        ));

        self::assertSame(302, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertSame('invalid_scope', $query['error']);
        self::assertSame('test-state-value', $query['state']);
    }

    public function testUserFlowRefusesAnUnknownAudienceWithARedirect(): void
    {
        // The redirect URI is already established, so the error goes back to the client.
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams(
            $challenge,
            ['audience' => 'https://nothing.test/'],
        ));

        self::assertSame(302, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertSame('invalid_target', $query['error']);
        self::assertArrayNotHasKey('code', $query);
    }

    public function testUserFlowRefusesAMalformedAudience(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams($challenge, ['audience' => 'not a uri']));

        self::assertSame('invalid_request', self::locationQuery($response)['error']);
    }

    public function testUserFlowWithoutAnAudienceIsUnchanged(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        self::assertSame(200, $this->post('/oauth2/token', $this->tokenRequest($code, $verifier))->getStatusCode());
        self::assertNull($this->onlyRow('oauth2_access_tokens')['audience']);
    }

    public function testAPermissionWithdrawnBeforeRedemptionIsNotIssued(): void
    {
        // Scope is narrowed at issuance and re-checked at redemption: the code was
        // approved for `invoices:write`, the API no longer defines it by the time the
        // code is spent, and the token carries what is still true.
        $this->loggedIn();
        $this->publicClient();
        $api = $this->invoicesApi();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid invoices:read invoices:write', 'audience' => self::INVOICES_API],
        );

        $this->dropWritePermission($api);
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read'],
            explode(' ', (string) self::json($response)['scope']),
        );
    }

    public function testACodeForAnApiDeletedBeforeRedemptionIsRefused(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $api = $this->invoicesApi();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid invoices:read', 'audience' => self::INVOICES_API],
        );

        $this->container()->get(ResourceServerRepository::class)->delete($api->id);
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertSame(0, TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_access_tokens'));
    }

    public function testASystemApisPermissionsAreNotIssuedToAUserYet(): void
    {
        // Until roles exist (Step 10) no user holds any of the Management API's
        // permissions, so asking for one is refused rather than granted to everybody.
        $this->loggedIn();
        $this->publicClient();
        $api = $this->container()->get(RegisterManagementApi::class)();
        [, $challenge] = $this->makePkcePair();

        $response = $this->get('/oauth2/authorize', $this->authorizeParams(
            $challenge,
            ['scope' => 'openid read:users', 'audience' => $api->identifier->value],
        ));

        self::assertSame('access_denied', self::locationQuery($response)['error']);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private function invoicesApi(): ResourceServer
    {
        return $this->anApi(self::INVOICES_API, ['invoices:read', 'invoices:write']);
    }

    /** The machine client {@see MachineFixtures::machineApi()} already registered. */
    private function m2mClientOnly(): Client
    {
        $client = $this->container()->get(ClientRepository::class)
            ->find(ClientId::fromString(self::TEST_M2M_CLIENT_ID));
        self::assertNotNull($client);

        return $client;
    }

    private function dropWritePermission(ResourceServer $api): void
    {
        $this->container()->get(ResourceServerRepository::class)->save(
            $api->withPermissions([Permission::of('invoices:read')]),
        );
    }
}
