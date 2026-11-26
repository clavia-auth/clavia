<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Audit\AuditEventType;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * SCIM groups and the roles they grant (RFC 7644; docs/design/scim-provisioning.md §5.5, slice 4): a
 * group named as a provisionable role gives it to its members and takes it back, a role given by hand
 * stays, and no group can ever give a Management API role.
 */
final class ScimGroupsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string GROUPS = '/scim/v2/Groups';
    private const string PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

    private string $token = '';
    private string $tokenId = '';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->freezeClock('2026-01-15T10:00:00Z');
        $this->adminToken();
        $issued = self::document($this->api(RequestMethodInterface::METHOD_POST, '/api/v1/provisioning-tokens', [
            'connection' => 'password',
            'description' => 'Entra ID',
        ]));
        self::assertIsString($issued['token']);
        self::assertIsString($issued['id']);
        $this->token = $issued['token'];
        $this->tokenId = $issued['id'];
    }

    public function testAGroupGivesItsProvisionableRoleToItsMembersAndTakesItBack(): void
    {
        $role = $this->role('Engineers', provisionable: true);
        [$ada, $grace] = [$this->account('ada@x.test'), $this->account('grace@x.test')];

        $created = $this->scim(RequestMethodInterface::METHOD_POST, self::GROUPS, [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Engineers',
            'externalId' => 'eng',
            'members' => [['value' => $ada]],
        ]);

        self::assertStatus(StatusCodeInterface::STATUS_CREATED, $created);
        $group = self::document($created);
        self::assertIsString($group['id']);
        self::assertSame(['Engineers'], $this->rolesOf($ada));
        $given = TestStorage::database()->fetchOne(
            "SELECT actor_kind, actor_provisioning_token_id FROM audit_events WHERE type = 'user.roles_changed'",
        );
        self::assertSame(['actor_kind' => 'provisioning', 'actor_provisioning_token_id' => $this->tokenId], $given);
        $path = self::GROUPS . '/' . $group['id'];

        // Entra ID's membership changes: Grace in, Ada out.
        $this->patchGroup($group['id'], ['op' => 'Add', 'path' => 'members', 'value' => [['value' => $grace]]]);
        $this->patchGroup($group['id'], ['op' => 'Remove', 'path' => 'members[value eq "' . $ada . '"]']);

        self::assertSame([], $this->rolesOf($ada));
        self::assertSame(['Engineers'], $this->rolesOf($grace));
        $read = self::document($this->scim(RequestMethodInterface::METHOD_GET, $path));
        self::assertSame([$grace], array_column((array) $read['members'], 'value'));
        $slim = self::document($this->scim(RequestMethodInterface::METHOD_GET, $path . '?excludedAttributes=members'));
        self::assertArrayNotHasKey('members', $slim);

        $deleted = $this->scim(RequestMethodInterface::METHOD_DELETE, $path);

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $deleted->getStatusCode());
        self::assertSame([], $this->rolesOf($grace), 'Taken back with the group.');
        unset($role);
    }

    public function testARoleGivenByHandStaysWhenTheGroupLetsGo(): void
    {
        $role = $this->role('Engineers', provisionable: true);
        $ada = $this->account('ada@x.test');
        $assigned = $this->api(
            RequestMethodInterface::METHOD_PUT,
            '/api/v1/users/' . $ada . '/roles',
            ['role_ids' => [$role]],
        );
        self::assertStatus(StatusCodeInterface::STATUS_OK, $assigned);
        $group = $this->group('Engineers', [$ada]);

        $this->patchGroup($group, ['op' => 'replace', 'path' => 'members', 'value' => []]);

        self::assertSame(['Engineers'], $this->rolesOf($ada), "The operator's, not the group's.");
    }

    public function testOnlyAProvisionableRoleIsGivenAndARenameMovesTheGrant(): void
    {
        $this->role('Analysts', provisionable: false);
        $this->role('Engineers', provisionable: true);
        $ada = $this->account('ada@x.test');
        $group = $this->group('Analysts', [$ada]);
        self::assertSame([], $this->rolesOf($ada), 'Not provisionable: nothing.');

        $this->patchGroup($group, ['op' => 'replace', 'path' => 'displayName', 'value' => 'Engineers']);

        self::assertSame(['Engineers'], $this->rolesOf($ada));
    }

    public function testAnOperatorMakingARoleProvisionableOrNotMovesItsGrants(): void
    {
        $role = $this->role('Engineers', provisionable: false);
        $ada = $this->account('ada@x.test');
        $this->group('Engineers', [$ada]);
        self::assertSame([], $this->rolesOf($ada));

        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/roles/' . $role, ['provisionable' => true]);
        self::assertSame(['Engineers'], $this->rolesOf($ada), 'Granted as the flag turns on.');
        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/roles/' . $role, ['provisionable' => false]);
        self::assertSame([], $this->rolesOf($ada), 'Taken back as it turns off.');
    }

    public function testNoGroupCanGiveAManagementApiRole(): void
    {
        $api = $this->managementApi();
        $created = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/roles', [
            'name' => 'Administrators',
            'provisionable' => true,
            'permissions' => [['resource_server_id' => $api->id->value, 'value' => 'read:users']],
        ]);
        $plain = self::document($this->api(RequestMethodInterface::METHOD_POST, '/api/v1/roles', [
            'name' => 'Administrators',
            'permissions' => [['resource_server_id' => $api->id->value, 'value' => 'read:users']],
        ]));
        self::assertIsString($plain['id']);
        $flagged = $this->api(
            RequestMethodInterface::METHOD_PATCH,
            '/api/v1/roles/' . $plain['id'],
            ['provisionable' => true],
        );
        $ada = $this->account('ada@x.test');
        $this->group('Administrators', [$ada]);

        self::assertStatus(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $created);
        self::assertStatus(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $flagged);
        self::assertSame([], $this->rolesOf($ada), 'Never an administrator through a group.');
    }

    public function testAGroupIsHeldToItsConnection(): void
    {
        $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
            'name' => 'staff',
            'display_name' => 'Staff',
            'strategy' => 'database',
        ]);
        $theirs = self::document($this->api(RequestMethodInterface::METHOD_POST, '/api/v1/provisioning-tokens', [
            'connection' => 'staff',
            'description' => 'Okta',
        ]))['token'];
        self::assertIsString($theirs);
        $ada = $this->account('ada@x.test');
        $group = $this->group('Engineers', []);

        $ops = ['displayName' => 'Ops', 'members' => [['value' => $ada]]];
        $stranger = $this->scim(RequestMethodInterface::METHOD_POST, self::GROUPS, $ops, $theirs);
        $elsewhere = $this->scim(RequestMethodInterface::METHOD_GET, self::GROUPS . '/' . $group, null, $theirs);
        $twice = $this->scim(RequestMethodInterface::METHOD_POST, self::GROUPS, ['displayName' => 'ENGINEERS']);
        $filter = rawurlencode('displayName eq "engineers"');
        $found = self::document($this->scim(RequestMethodInterface::METHOD_GET, self::GROUPS . '?filter=' . $filter));
        $noUserName = $this->scim(
            RequestMethodInterface::METHOD_GET,
            self::GROUPS . '?filter=' . rawurlencode('userName eq "x"'),
        );

        self::assertStatus(StatusCodeInterface::STATUS_BAD_REQUEST, $stranger, "Another connection's account.");
        self::assertStatus(StatusCodeInterface::STATUS_NOT_FOUND, $elsewhere);
        self::assertStatus(StatusCodeInterface::STATUS_CONFLICT, $twice);
        self::assertSame(1, $found['totalResults']);
        self::assertStatus(StatusCodeInterface::STATUS_BAD_REQUEST, $noUserName, 'A group has no userName.');
    }

    private function role(string $name, bool $provisionable): string
    {
        $created = $this->api(
            RequestMethodInterface::METHOD_POST,
            '/api/v1/roles',
            ['name' => $name, 'provisionable' => $provisionable],
        );
        self::assertStatus(StatusCodeInterface::STATUS_CREATED, $created);
        $id = self::document($created)['id'];
        self::assertIsString($id);

        return $id;
    }

    /** @param list<string> $members */
    private function group(string $name, array $members): string
    {
        $created = $this->scim(RequestMethodInterface::METHOD_POST, self::GROUPS, [
            'displayName' => $name,
            'members' => array_map(static fn (string $id): array => ['value' => $id], $members),
        ]);
        self::assertStatus(StatusCodeInterface::STATUS_CREATED, $created);
        $id = self::document($created)['id'];
        self::assertIsString($id);

        return $id;
    }

    /** @param array<string, mixed> $operation */
    private function patchGroup(string $id, array $operation): void
    {
        $patched = $this->scim(RequestMethodInterface::METHOD_PATCH, self::GROUPS . '/' . $id, self::patch($operation));
        self::assertStatus(StatusCodeInterface::STATUS_OK, $patched);
    }

    private static function assertStatus(int $status, ResponseInterface $response, string $message = ''): void
    {
        self::assertSame($status, $response->getStatusCode(), trim($message . ' ' . (string) $response->getBody()));
    }

    private function account(string $email): string
    {
        $created = $this->scim(RequestMethodInterface::METHOD_POST, '/scim/v2/Users', ['userName' => $email]);
        self::assertStatus(StatusCodeInterface::STATUS_CREATED, $created);
        $id = self::document($created)['id'];
        self::assertIsString($id);

        return $id;
    }

    /** @return list<string> */
    private function rolesOf(string $user): array
    {
        /** @var list<string> */
        return array_column(
            TestStorage::database()->fetchAll(
                'SELECT roles.name FROM user_roles JOIN roles ON roles.id = user_roles.role_id '
                . 'WHERE user_roles.user_id = :user ORDER BY roles.name',
                ['user' => $user],
            ),
            'name',
        );
    }

    /**
     * @param array<string, mixed> ...$operations
     *
     * @return array<string, mixed>
     */
    private static function patch(array ...$operations): array
    {
        return ['schemas' => [self::PATCH_OP], 'Operations' => $operations];
    }

    /** @param array<string, mixed>|null $body */
    private function scim(
        string $method,
        string $path,
        ?array $body = null,
        ?string $token = null,
    ): ResponseInterface {
        $headers = ['Authorization' => 'Bearer ' . ($token ?? $this->token)];
        if ($body !== null) {
            $headers['Content-Type'] = 'application/scim+json';
        }

        return $this->request(
            $method,
            $path,
            $headers,
            self::MANAGEMENT_HOST,
            $body === null ? '' : json_encode($body, JSON_THROW_ON_ERROR),
        );
    }
}
