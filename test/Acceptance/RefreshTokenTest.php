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
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The refresh token grant (RFC 6749 §6), with rotation.
 *
 * What matters is not that a refresh works but what happens when a token is seen twice.
 * Rotation makes every refresh token single-use; a replay is evidence that two parties
 * hold the chain, and the whole family goes. Around that: scope only narrows, roles are
 * read again, the account is re-checked, and a client gets a refresh token only if it
 * was registered for one.
 */
final class RefreshTokenTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string INVOICES = 'https://invoices.test/api/';

    // ── Issuance ────────────────────────────────────────────────────────────────

    public function testIssuedWithTheCodesTokensToAClientRegisteredForIt(): void
    {
        $user = $this->loggedIn();
        $this->refreshingClient();

        $token = $this->signIn();

        $refreshToken = $token['refresh_token'] ?? null;
        self::assertIsString($refreshToken);
        $stored = $this->refreshRow($refreshToken);
        // A digest, like everything else a client presents.
        self::assertStringNotContainsString($refreshToken, implode('|', array_map(strval(...), $stored)));
        self::assertSame($stored['id'], $stored['family_id'], 'The first token of a chain is its own family.');
        self::assertSame($user->id->value, $stored['user_id']);
        self::assertNull($stored['used_at']);
        // The access token issued with it carries the family, for revocation.
        self::assertSame($stored['family_id'], $this->onlyRow('oauth2_access_tokens')['refresh_family_id']);
    }

    public function testNoAmountOfRefreshingOutlivesTheFamilysDeadline(): void
    {
        $this->boot([
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
            'CLAVIA_REFRESH_TOKEN_ABSOLUTE_LIFETIME' => '120',
        ]);
        $clock = $this->freezeClock();
        $this->user();
        $this->refreshingClient();

        $first = $this->signIn();
        $stored = $this->refreshRow((string) $first['refresh_token']);

        // The idle limit (days) is longer than the family's (minutes): the family's
        // deadline is what the token carries.
        self::assertEquals(
            new DateTimeImmutable('2026-01-15T10:02:00Z'),
            new DateTimeImmutable((string) $stored['family_expires_at']),
        );
        self::assertSame($stored['family_expires_at'], $stored['expires_at']);

        $clock->advance(60);
        $second = self::json($this->refresh((string) $first['refresh_token']));
        $clock->advance(61);

        self::assertSame('invalid_grant', self::json($this->refresh((string) $second['refresh_token']))['error']);
    }

    // ── Rotation ────────────────────────────────────────────────────────────────

    public function testARefreshRotatesBothTokens(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $first = $this->signIn();

        $response = $this->refresh((string) $first['refresh_token']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $second = self::json($response);
        self::assertNotSame($first['access_token'], $second['access_token']);
        self::assertNotSame($first['refresh_token'], $second['refresh_token']);
        self::assertSame($first['scope'], $second['scope']);
        // A refresh renews access, not the sign-in (OIDC Core §12.2).
        self::assertArrayNotHasKey('id_token', $second);
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->userinfo((string) $second['access_token'])->getStatusCode(),
        );

        $spent = $this->refreshRow((string) $first['refresh_token']);
        $fresh = $this->refreshRow((string) $second['refresh_token']);
        self::assertNotNull($spent['used_at']);
        self::assertNull($fresh['used_at']);
        // Same family, same deadline, all the way down the chain.
        self::assertSame($spent['family_id'], $fresh['family_id']);
        self::assertSame($spent['family_expires_at'], $fresh['family_expires_at']);
    }

    public function testReplayingASpentTokenRevokesTheWholeFamily(): void
    {
        // RFC 6749 §10.4: neither the old token nor the new works afterwards, and every
        // access token the family minted goes with them — the thief's and the person's.
        $this->loggedIn();
        $this->refreshingClient();
        $first = $this->signIn();
        $second = self::json($this->refresh((string) $first['refresh_token']));

        $replay = $this->refresh((string) $first['refresh_token']);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $replay->getStatusCode());
        self::assertSame('invalid_grant', self::json($replay)['error']);
        self::assertSame('invalid_grant', self::json($this->refresh((string) $second['refresh_token']))['error']);
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->userinfo((string) $first['access_token'])->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->userinfo((string) $second['access_token'])->getStatusCode(),
        );
        self::assertSame(
            0,
            TestStorage::database()->fetchValue('SELECT count(*) FROM oauth2_refresh_tokens WHERE revoked_at IS NULL'),
        );
    }

    // ── What a refresh may and may not change ──────────────────────────────────

    public function testScopeMayNarrowButNeverWiden(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $first = $this->signIn('openid profile email');

        $widened = $this->refresh((string) $first['refresh_token'], 'openid profile email address');
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $widened->getStatusCode());
        self::assertSame('invalid_scope', self::json($widened)['error']);
        // Refused before the token was spent: the session survives over-asking.
        self::assertNull($this->refreshRow((string) $first['refresh_token'])['used_at']);

        $narrowed = self::json($this->refresh((string) $first['refresh_token'], 'openid'));
        self::assertSame('openid', $narrowed['scope']);
        // What was given up is not had back by asking: the narrowed scope is the new ceiling.
        $regained = $this->refresh((string) $narrowed['refresh_token'], 'openid profile');
        self::assertSame('invalid_scope', self::json($regained)['error']);
    }

    public function testTheAudienceIsCarriedAndCannotBeRetargeted(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $this->invoicesApi(enforce: false);
        $first = $this->signIn('openid invoices:read', self::INVOICES);

        $second = self::json($this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => (string) $first['refresh_token'],
            'audience' => 'https://elsewhere.test/',
        ]));

        // `audience` means nothing on a refresh: a family is for one API.
        self::assertSame(self::INVOICES, $this->accessRow((string) $second['access_token'])['audience']);
        self::assertEqualsCanonicalizing(['openid', 'invoices:read'], explode(' ', (string) $second['scope']));
    }

    public function testRolesAreReadAgainOnEveryRefresh(): void
    {
        $user = $this->loggedIn();
        $this->refreshingClient();
        $api = $this->invoicesApi(enforce: true);
        $role = $this->role('Everything', 'invoices:read invoices:write');
        $roles = $this->container()->get(RoleRepository::class);
        $roles->assign($role->id, $user->id, new DateTimeImmutable());
        $first = $this->signIn('openid invoices:read invoices:write', self::INVOICES);
        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read', 'invoices:write'],
            explode(' ', (string) $first['scope']),
        );

        // Withdrawn since the last refresh: honoured by this one.
        $roles->save($role->granting(array_values(array_filter(
            $role->permissions,
            static fn (GrantedPermission $granted): bool => $granted->value->value === 'invoices:read',
        ))));
        $narrowed = self::json($this->refresh((string) $first['refresh_token']));
        self::assertEqualsCanonicalizing(['openid', 'invoices:read'], explode(' ', (string) $narrowed['scope']));

        // Given back: honoured too, up to what was authorized at sign-in.
        $roles->save($role);
        $restored = self::json($this->refresh((string) $narrowed['refresh_token']));
        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read', 'invoices:write'],
            explode(' ', (string) $restored['scope']),
        );

        // Holding nothing: refused, and the token is not burnt by it.
        $roles->unassign($role->id, $user->id);
        $refused = $this->refresh((string) $restored['refresh_token']);
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertSame('invalid_grant', self::json($refused)['error']);
        self::assertNull($this->refreshRow((string) $restored['refresh_token'])['used_at']);
        self::assertTrue($api->enforcePolicies);
    }

    // ── Refusals ────────────────────────────────────────────────────────────────

    public function testAnExpiredTokenIsRefusedAndNeitherSpentNorRevoked(): void
    {
        $this->boot([
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
            'CLAVIA_REFRESH_TOKEN_LIFETIME' => '600',
        ]);
        $clock = $this->freezeClock();
        $this->user();
        $this->refreshingClient();
        $first = $this->signIn();

        $clock->advance(601);
        $response = $this->refresh((string) $first['refresh_token']);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        $stored = $this->refreshRow((string) $first['refresh_token']);
        self::assertNull($stored['used_at']);
        self::assertNull($stored['revoked_at']);
    }

    public function testAnUnknownTokenIsRefused(): void
    {
        $this->refreshingClient();

        $response = $this->refresh('not-a-token-anyone-issued');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testAnotherClientPresentingTheTokenIsRefusedWithoutBurningIt(): void
    {
        // Client ids are public, so a thief would present the right one: a wrong one is a
        // misconfiguration, and the rightful client refreshes on.
        $this->loggedIn();
        $this->refreshingClient();
        $this->confidentialClient([GrantType::AuthorizationCode, GrantType::RefreshToken]);
        $first = $this->signIn();

        $response = $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
            'refresh_token' => (string) $first['refresh_token'],
        ]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->refresh((string) $first['refresh_token'])->getStatusCode(),
        );
    }

    public function testAClientNotRegisteredForTheGrantIsRefused(): void
    {
        $this->loggedIn();
        $this->publicClient();
        self::assertArrayNotHasKey('refresh_token', $this->signIn());

        $response = $this->refresh('whatever');

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('unauthorized_client', self::json($response)['error']);
    }

    public function testADeactivatedAccountIsRefused(): void
    {
        $user = $this->loggedIn();
        $this->refreshingClient();
        $first = $this->signIn();
        $user->deactivate(new DateTimeImmutable());
        $this->container()->get(UserRepository::class)->save($user);

        $response = $this->refresh((string) $first['refresh_token']);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testAReplayedCodeRevokesTheFamilyItStarted(): void
    {
        // A leaked code that already bought a refresh token bought a session.
        $this->loggedIn();
        $this->refreshingClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);
        $first = self::json($this->post('/oauth2/token', $this->tokenRequest($code, $verifier)));
        $second = self::json($this->refresh((string) $first['refresh_token']));

        $replayed = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $replayed->getStatusCode());
        self::assertSame('invalid_grant', self::json($this->refresh((string) $second['refresh_token']))['error']);
        self::assertSame(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            $this->userinfo((string) $second['access_token'])->getStatusCode(),
        );
    }

    // ── Registration and discovery ─────────────────────────────────────────────

    public function testRefreshTokensWithoutTheCodeFlowCannotBeRegistered(): void
    {
        $this->adminToken();

        $response = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/clients', [
            'client_type' => 'public',
            'grant_types' => ['refresh_token'],
            'redirect_uris' => ['https://spa.test/callback'],
        ]);

        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $response->getStatusCode());
        $accepted = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/clients', [
            'client_type' => 'public',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'redirect_uris' => ['https://spa.test/callback'],
        ]);
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $accepted->getStatusCode(),
            (string) $accepted->getBody(),
        );
    }

    public function testDiscoveryAdvertisesTheGrant(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame(
            [
                'authorization_code',
                'client_credentials',
                'refresh_token',
                'urn:ietf:params:oauth:grant-type:device_code',
            ],
            $document['grant_types_supported'],
        );
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * The code flow as the signed-in person: the token response.
     *
     * @return array<array-key, mixed>
     */
    private function signIn(string $scope = 'openid profile', ?string $audience = null): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => $scope, 'audience' => $audience]);
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());

        return self::json($response);
    }

    /** Refresh as the public client: no secret, the token is the whole credential. */
    private function refresh(string $refreshToken, ?string $scope = null): ResponseInterface
    {
        $form = [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => $refreshToken,
        ];
        if ($scope !== null) {
            $form['scope'] = $scope;
        }

        return $this->post('/oauth2/token', $form);
    }

    private function userinfo(string $accessToken): ResponseInterface
    {
        return $this->request(
            RequestMethodInterface::METHOD_GET,
            '/oidc/userinfo',
            ['Authorization' => 'Bearer ' . $accessToken],
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function refreshRow(string $refreshToken): array
    {
        $row = TestStorage::database()->fetchOne(
            'SELECT * FROM oauth2_refresh_tokens WHERE token_hash = :hash',
            ['hash' => Digest::of($refreshToken)->toString()],
        );
        self::assertNotNull($row);

        return $row;
    }

    /**
     * @return array<string, mixed>
     */
    private function accessRow(string $accessToken): array
    {
        $row = TestStorage::database()->fetchOne(
            'SELECT * FROM oauth2_access_tokens WHERE token_hash = :hash',
            ['hash' => Digest::of($accessToken)->toString()],
        );
        self::assertNotNull($row);

        return $row;
    }

    private function invoicesApi(bool $enforce): ResourceServer
    {
        $api = $this->anApi(self::INVOICES, ['invoices:read', 'invoices:write'])->enforcingPolicies($enforce);
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    private function role(string $name, string $permissions): Role
    {
        return $this->container()->get(EnsureRole::class)(
            $name,
            '',
            Audience::fromString(self::INVOICES),
            ScopeSet::fromString($permissions),
        );
    }
}
