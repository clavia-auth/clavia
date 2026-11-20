<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use DateTimeImmutable;
use Psr\Http\Message\ResponseInterface;

/**
 * Roles and permissions — ported from the Python suite's `test_rbac.py`.
 *
 * Two halves. Issuance, the part that matters: an API that enforces roles narrows a
 * person's token to what their roles grant, refuses somebody who holds nothing, and reads
 * roles again for every token. Then the API: roles are managed like any other resource,
 * and only `update:roles` confers authority.
 */
final class RbacTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string INVOICES = 'https://invoices.test/api/';
    private const string ROLES = '/api/v1/roles';

    // ── Issuance ────────────────────────────────────────────────────────────────

    public function testWithoutRolesTheApisPermissionsAreTheOnlyBound(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(enforce: false);

        $token = self::json($this->userFlow('openid invoices:read invoices:write'));

        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read', 'invoices:write'],
            explode(' ', (string) $token['scope']),
        );
    }

    public function testRolesNarrowTheTokenToWhatTheyGrant(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(enforce: true);
        $this->give($user, $this->role('Reader', self::INVOICES, 'invoices:read'));

        $response = $this->userFlow('openid invoices:read invoices:write');

        // Narrowed, not refused: asking for more than you hold gets what you hold.
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response);
        self::assertEqualsCanonicalizing(['openid', 'invoices:read'], explode(' ', (string) $token['scope']));
        self::assertSame($token['scope'], $this->onlyRow('oauth2_access_tokens')['scope']);
    }

    public function testSomebodyHoldingNothingIsRefusedBeforeACodeExists(): void
    {
        // Sent back to the client, not an empty token that would fail every call with
        // nothing to say why.
        $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(enforce: true);

        $response = $this->userFlow('openid invoices:read');

        self::assertSame(302, $response->getStatusCode());
        $query = self::locationQuery($response);
        self::assertSame('access_denied', $query['error']);
        self::assertSame('test-state-value', $query['state']);
        self::assertArrayNotHasKey('code', $query);
    }

    public function testARoleTakenAwayBeforeRedemptionIsHonoured(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $this->invoicesApi(enforce: true);
        $reader = $this->role('Reader', self::INVOICES, 'invoices:read');
        $this->give($user, $reader);
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode(
            $challenge,
            ['scope' => 'openid invoices:read', 'audience' => self::INVOICES],
        );

        $this->roles()->unassign($reader->id, $user->id);
        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testAPermissionTheApiStopsDefiningLeavesEveryRole(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $api = $this->invoicesApi(enforce: true);
        $role = $this->role('Everything', self::INVOICES, 'invoices:read invoices:write');
        $this->give($user, $role);

        $this->container()->get(ResourceServerRepository::class)->save(
            $api->withPermissions([Permission::of('invoices:read')]),
        );

        self::assertSame('invoices:read', $this->roles()->find($role->id)?->grantsOn($api->id)->toString());
        // What survives is still granted…
        self::assertEqualsCanonicalizing(
            ['openid', 'invoices:read'],
            explode(' ', (string) self::json($this->userFlow('openid invoices:read'))['scope']),
        );
        // …and asking for the withdrawn one is refused by the API's own definition, before
        // roles come into it.
        self::assertSame('invalid_scope', self::locationQuery($this->userFlow('openid invoices:write'))['error']);
    }

    public function testMachineClientsAreGovernedByTheirGrantsNotByRoles(): void
    {
        // Roles are about people. A client acting as itself has none; its client grant is
        // its authority, whether or not the API enforces roles.
        $api = $this->invoicesApi(enforce: true);
        $this->grantClient($this->m2mClient(), $api, 'invoices:read');

        $response = $this->requestMachineToken(['audience' => self::INVOICES]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame('invoices:read', self::json($response)['scope']);
    }

    // ── The Management API, through the dashboard's eyes ───────────────────────

    public function testAnOperatorsTokenIsNarrowedToTheirRoleAndHeldToIt(): void
    {
        $user = $this->loggedIn();
        $this->publicClient();
        $api = $this->managementApi();
        $readOnly = array_values(array_filter(
            $this->allManagementScopes(),
            static fn (string $scope): bool => str_starts_with($scope, 'read:'),
        ));
        $this->give($user, $this->role('Support', self::MANAGEMENT_API, implode(' ', $readOnly)));

        $response = $this->userFlow('openid ' . implode(' ', $this->allManagementScopes()), $api->identifier->value);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        $token = self::json($response);
        self::assertEqualsCanonicalizing(['openid', ...$readOnly], explode(' ', (string) $token['scope']));
        $accessToken = (string) $token['access_token'];
        self::assertSame(200, $this->api('GET', '/api/v1/users', token: $accessToken)->getStatusCode());
        $forbidden = $this->api(
            'POST',
            '/api/v1/users',
            ['email' => 'x@clavia.dev', 'password' => 'a-good-password'],
            token: $accessToken,
        );
        self::assertSame(403, $forbidden->getStatusCode());
        self::assertSame('insufficient_scope', self::document($forbidden)['error']);
    }

    public function testSomebodyWithNoRoleCannotReachTheManagementApi(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $api = $this->managementApi();

        $response = $this->userFlow('openid read:users', $api->identifier->value);

        self::assertSame('access_denied', self::locationQuery($response)['error']);
    }

    public function testTheManagementApiCannotHaveRolesTurnedOff(): void
    {
        $this->adminToken();
        $id = $this->managementApi()->id->value;

        $response = $this->api('PATCH', '/api/v1/resource-servers/' . $id, ['enforce_policies' => false]);

        self::assertSame(409, $response->getStatusCode());
        self::assertTrue(self::document($this->api('GET', '/api/v1/resource-servers/' . $id))['enforce_policies']);
    }

    public function testRolesCanBeSwitchedOnAndOffForAnOrdinaryApi(): void
    {
        $this->adminToken();

        $created = self::document($this->api(
            'POST',
            '/api/v1/resource-servers',
            ['identifier' => 'https://ordinary.test/', 'enforce_policies' => true],
        ));
        self::assertTrue($created['enforce_policies']);

        $patched = $this->api(
            'PATCH',
            '/api/v1/resource-servers/' . (string) $created['id'],
            ['enforce_policies' => false],
        );
        self::assertSame(200, $patched->getStatusCode());
        self::assertFalse(self::document($patched)['enforce_policies']);
    }

    // ── Roles over the API ──────────────────────────────────────────────────────

    public function testARoleFromDefinitionToDeletion(): void
    {
        $this->adminToken();
        $api = $this->managementApi();
        $user = $this->user();
        $reference = static fn (string $value): array => ['resource_server_id' => $api->id->value, 'value' => $value];

        $created = $this->api('POST', self::ROLES, [
            'name' => 'Support',
            'description' => 'Read-only for the help desk',
            'permissions' => [$reference('read:users')],
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        $role = self::document($created);
        $id = (string) $role['id'];
        self::assertStringStartsWith('rol_', $id);
        self::assertSame(self::ROLES . '/' . $id, $created->getHeaderLine('Location'));
        self::assertSame(
            [[
                'resource_server_id' => $api->id->value,
                'resource_server_identifier' => self::MANAGEMENT_API,
                'value' => 'read:users',
                'description' => 'View end users',
            ]],
            $role['permissions'],
        );

        $patched = $this->api('PATCH', self::ROLES . '/' . $id, [
            'permissions' => [$reference('read:users'), $reference('read:clients')],
        ]);
        self::assertSame(200, $patched->getStatusCode(), (string) $patched->getBody());
        self::assertSame(['read:clients', 'read:users'], self::values(self::document($patched)['permissions']));

        $body = ['user_ids' => [$user->id->value]];
        self::assertSame(204, $this->api('POST', self::ROLES . '/' . $id . '/users', $body)->getStatusCode());
        self::assertSame(204, $this->api('POST', self::ROLES . '/' . $id . '/users', $body)->getStatusCode());
        $holders = self::document($this->api('GET', self::ROLES . '/' . $id . '/users'));
        self::assertSame(1, $holders['total'], 'Giving a role again is not a second assignment.');
        /** @var list<array{email: string}> $items */
        $items = $holders['items'];
        self::assertSame(self::TEST_USER_EMAIL, $items[0]['email']);

        $roles = self::document($this->api('GET', '/api/v1/users/' . $user->id->value . '/roles'));
        self::assertSame(['Support'], array_column($roles, 'name'));
        /** @var list<array{value: string, roles: list<array{id: string, name: string}>}> $effective */
        $effective = self::document($this->api('GET', '/api/v1/users/' . $user->id->value . '/permissions'));
        self::assertSame(['read:clients', 'read:users'], array_column($effective, 'value'));
        self::assertSame([['id' => $id, 'name' => 'Support']], $effective[0]['roles']);

        $taken = $this->api('DELETE', self::ROLES . '/' . $id . '/users/' . $user->id->value);
        self::assertSame(204, $taken->getStatusCode());
        self::assertSame(0, self::document($this->api('GET', self::ROLES . '/' . $id . '/users'))['total']);

        self::assertSame(204, $this->api('DELETE', self::ROLES . '/' . $id)->getStatusCode());
        self::assertSame(404, $this->api('GET', self::ROLES . '/' . $id)->getStatusCode());
    }

    public function testARoleCannotGrantWhatNoApiDefines(): void
    {
        $this->adminToken();
        $api = $this->managementApi();

        foreach ([[$api->id->value, 'launch:missiles'], ['rs_nonexistent00000', 'read:users']] as [$apiId, $value]) {
            $response = $this->api('POST', self::ROLES, [
                'name' => 'Ghost',
                'permissions' => [['resource_server_id' => $apiId, 'value' => $value]],
            ]);

            self::assertSame(422, $response->getStatusCode(), $value);
        }
        self::assertSame(0, self::document($this->api('GET', self::ROLES))['total']);
    }

    public function testARoleNameIsTakenOnce(): void
    {
        $this->adminToken();
        self::assertSame(201, $this->api('POST', self::ROLES, ['name' => 'Support'])->getStatusCode());

        self::assertSame(409, $this->api('POST', self::ROLES, ['name' => 'Support'])->getStatusCode());
    }

    public function testSettingSomebodysRolesReplacesThem(): void
    {
        $this->adminToken();
        $user = $this->user();
        $a = $this->role('A', self::MANAGEMENT_API, 'read:users');
        $b = $this->role('B', self::MANAGEMENT_API, 'read:users');
        $this->give($user, $a);

        $path = '/api/v1/users/' . $user->id->value . '/roles';

        $response = $this->api('PUT', $path, ['role_ids' => [$b->id->value]]);

        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame(['B'], array_column(self::document($response), 'name'));
        $unknown = $this->api('PUT', $path, ['role_ids' => [$a->id->value, 'rol_doesnotexist0000']]);
        self::assertSame(404, $unknown->getStatusCode());
        self::assertSame(
            ['B'],
            array_map(static fn (Role $role): string => $role->name, $this->roles()->rolesOf($user->id)),
            'Refused whole, not applied in part.',
        );
    }

    public function testConferringAuthorityNeedsUpdateRoles(): void
    {
        // `update:users` edits an account; putting authority on it is another scope.
        $this->adminToken(['update:users', 'read:users']);
        $user = $this->user();

        $response = $this->api('PUT', '/api/v1/users/' . $user->id->value . '/roles', ['role_ids' => []]);

        self::assertSame(403, $response->getStatusCode());
        self::assertStringContainsString('scope="update:roles"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testRolesAreSearchedByNameAndDescription(): void
    {
        $this->adminToken();
        $this->api('POST', self::ROLES, ['name' => 'Support', 'description' => 'Read-only for the help desk']);
        $this->api('POST', self::ROLES, ['name' => 'Billing', 'description' => 'Invoicing']);

        self::assertSame(1, self::document($this->api('GET', self::ROLES, query: ['q' => 'support']))['total']);
        self::assertSame(1, self::document($this->api('GET', self::ROLES, query: ['q' => 'help desk']))['total']);
        self::assertSame(2, self::document($this->api('GET', self::ROLES))['total']);
    }

    public function testTheAdministratorBootstrapIsIdempotent(): void
    {
        $this->managementApi();

        $first = $this->role(SeedManagementAccess::ADMINISTRATOR_ROLE, self::MANAGEMENT_API, null);
        $again = $this->role(SeedManagementAccess::ADMINISTRATOR_ROLE, self::MANAGEMENT_API, null);

        self::assertSame($first->id->value, $again->id->value);
        self::assertEqualsCanonicalizing(
            $this->allManagementScopes(),
            array_map(static fn (GrantedPermission $granted): string => $granted->value->value, $again->permissions),
        );
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private function invoicesApi(bool $enforce): ResourceServer
    {
        $api = $this->anApi(self::INVOICES, ['invoices:read', 'invoices:write'])->enforcingPolicies($enforce);
        $this->container()->get(ResourceServerRepository::class)->save($api);

        return $api;
    }

    /** Authorize, then redeem, as the signed-in person; the refusal when there is no code. */
    private function userFlow(string $scope, ?string $audience = self::INVOICES): ResponseInterface
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $authorized = $this->get('/oauth2/authorize', $this->authorizeParams(
            $challenge,
            ['scope' => $scope, 'audience' => $audience],
        ));
        if (! array_key_exists('code', self::locationQuery($authorized))) {
            return $authorized;
        }

        return $this->post('/oauth2/token', $this->tokenRequest($this->extractCode($authorized), $verifier));
    }

    private function role(string $name, string $api, ?string $permissions): Role
    {
        return $this->container()->get(EnsureRole::class)(
            $name,
            '',
            Audience::fromString($api),
            $permissions === null ? null : ScopeSet::fromString($permissions),
        );
    }

    private function give(User $user, Role $role): void
    {
        $this->roles()->assign($role->id, $user->id, new DateTimeImmutable());
    }

    private function roles(): RoleRepository
    {
        return $this->container()->get(RoleRepository::class);
    }

    /** @return list<string> */
    private function allManagementScopes(): array
    {
        return array_map(
            static fn (ManagementPermission $permission): string => $permission->value,
            ManagementPermission::cases(),
        );
    }

    /**
     * @param mixed $permissions A decoded JSON array of permissions.
     *
     * @return list<mixed>
     */
    private static function values(mixed $permissions): array
    {
        self::assertIsArray($permissions);

        return array_column($permissions, 'value');
    }
}
