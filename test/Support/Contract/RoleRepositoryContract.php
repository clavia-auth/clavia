<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\Scope;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see RoleRepository} does — the foreign keys included: a permission an API
 * stops defining, a deleted role and a deleted account all leave no trace in the roles.
 */
trait RoleRepositoryContract
{
    abstract protected function roles(): RoleRepository;

    abstract protected function resourceServers(): ResourceServerRepository;

    abstract protected function users(): UserRepository;

    #[Test]
    public function aSavedRoleIsReadBackWithWhatItGrants(): void
    {
        $api = $this->invoicesApi();
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Billing', [[$api, 'invoices:write'], [$api, 'invoices:read']]);
        $this->roles()->save($role);

        $read = $this->roles()->find($role->id);

        self::assertNotNull($read);
        self::assertSame('Billing', $read->name);
        self::assertSame('Bills people', $read->description);
        self::assertSame('invoices:read invoices:write', $read->grantsOn($api->id)->toString());
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $read->createdAt);
        self::assertSame($role->id->value, $this->roles()->findByName('Billing')?->id->value);
        self::assertNull($this->roles()->findByName('billing'));
        self::assertNull($this->roles()->find(RoleId::fromString('rol_zzzzzzzzzzzzzzzz')));
    }

    #[Test]
    public function aRoleNameIsTakenOnce(): void
    {
        $this->roles()->save($this->aRole('rol_aaaaaaaaaaaaaaaa', 'Billing', []));

        $this->expectException(AlreadyExists::class);
        $this->roles()->save($this->aRole('rol_bbbbbbbbbbbbbbbb', 'Billing', []));
    }

    #[Test]
    public function savingAgainReplacesTheNameTheDescriptionAndTheGrants(): void
    {
        $api = $this->invoicesApi();
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Billing', [[$api, 'invoices:read']]);
        $this->roles()->save($role);

        $this->roles()->save(
            $role->renamed('Accounts')->described('Keeps the books')->granting([
                new GrantedPermission($api->id, Scope::fromString('invoices:write')),
            ]),
        );

        $read = $this->roles()->find($role->id);
        self::assertSame('Accounts', $read?->name);
        self::assertSame('Keeps the books', $read?->description);
        self::assertSame('invoices:write', $read?->grantsOn($api->id)->toString());
    }

    #[Test]
    public function aPermissionTheApiStopsDefiningLeavesEveryRole(): void
    {
        $api = $this->invoicesApi();
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Billing', [[$api, 'invoices:read'], [$api, 'invoices:write']]);
        $this->roles()->save($role);
        $user = $this->aRoleHolder('jane@example.com');
        $this->roles()->assign($role->id, $user, new DateTimeImmutable());

        $this->resourceServers()->save($api->withPermissions([Permission::of('invoices:read')]));

        self::assertSame('invoices:read', $this->roles()->find($role->id)?->grantsOn($api->id)->toString());
        self::assertSame('invoices:read', $this->roles()->permissionsHeld($user, $api->id)->toString());
    }

    #[Test]
    public function rolesArePagedNewestFirstAndSearchedByNameAndDescription(): void
    {
        $this->roles()->save($this->aRole('rol_aaaaaaaaaaaaaaaa', 'Support', [], 'Help desk', '2026-01-15T10:00:00Z'));
        $this->roles()->save($this->aRole('rol_bbbbbbbbbbbbbbbb', 'Billing', [], 'Invoicing', '2026-01-15T11:00:00Z'));

        self::assertSame(['Billing', 'Support'], $this->roleNames($this->roles()->page(PageRequest::of())->items));
        self::assertSame(1, $this->roles()->page(PageRequest::of(search: 'SUPPORT'))->total);
        self::assertSame(1, $this->roles()->page(PageRequest::of(search: 'help desk'))->total);
        self::assertSame(['Billing', 'Support'], $this->roleNames($this->roles()->all()));
    }

    /**
     * @param list<Role> $roles
     *
     * @return list<string>
     */
    private function roleNames(array $roles): array
    {
        return array_map(static fn (Role $role): string => $role->name, $roles);
    }

    #[Test]
    public function aRoleIsGivenOnceAndTakenAway(): void
    {
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Support', []);
        $this->roles()->save($role);
        $jane = $this->aRoleHolder('jane@example.com');
        $john = $this->aRoleHolder('john@example.com');

        $this->roles()->assign($role->id, $jane, new DateTimeImmutable('2026-01-15T10:00:00Z'));
        $this->roles()->assign($role->id, $john, new DateTimeImmutable('2026-01-15T11:00:00Z'));
        $this->roles()->assign($role->id, $jane, new DateTimeImmutable('2026-01-15T12:00:00Z'));

        $holders = $this->roles()->holders($role->id, PageRequest::of());
        self::assertSame(2, $holders->total);
        self::assertSame(
            [$john->value, $jane->value],
            array_map(static fn (UserId $id): string => $id->value, $holders->items),
            'Most recently assigned first; giving it again is not a new assignment.',
        );
        self::assertSame(['Support'], $this->roleNames($this->roles()->rolesOf($jane)));

        $this->roles()->unassign($role->id, $jane);
        $this->roles()->unassign($role->id, $jane);

        self::assertSame([], $this->roles()->rolesOf($jane));
        self::assertSame(1, $this->roles()->holders($role->id, PageRequest::of())->total);
    }

    #[Test]
    public function replacingSomebodysRolesLeavesExactlyTheOnesNamed(): void
    {
        $a = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'A', []);
        $b = $this->aRole('rol_bbbbbbbbbbbbbbbb', 'B', []);
        $c = $this->aRole('rol_cccccccccccccccc', 'C', []);
        foreach ([$a, $b, $c] as $role) {
            $this->roles()->save($role);
        }
        $user = $this->aRoleHolder('jane@example.com');
        $this->roles()->assign($a->id, $user, new DateTimeImmutable());
        $this->roles()->assign($b->id, $user, new DateTimeImmutable());

        $this->roles()->replaceRolesOf($user, [$c->id, $b->id], new DateTimeImmutable());

        self::assertSame(['B', 'C'], $this->roleNames($this->roles()->rolesOf($user)));

        $this->roles()->replaceRolesOf($user, [], new DateTimeImmutable());
        self::assertSame([], $this->roles()->rolesOf($user));
    }

    #[Test]
    public function whatSomebodyHoldsOnAnApiIsWhatAllTheirRolesGrantThere(): void
    {
        $invoices = $this->invoicesApi();
        $reports = $this->anApiWithRoles(
            'rs_reports000000001',
            'https://reports.example/api/',
            ['invoices:read', 'export'],
        );
        $this->resourceServers()->save($reports);
        $this->roles()->save($this->aRole('rol_aaaaaaaaaaaaaaaa', 'Reader', [[$invoices, 'invoices:read']]));
        $this->roles()->save(
            $this->aRole('rol_bbbbbbbbbbbbbbbb', 'Writer', [[$invoices, 'invoices:write'], [$reports, 'export']]),
        );
        $user = $this->aRoleHolder('jane@example.com');
        $other = $this->aRoleHolder('john@example.com');
        $this->roles()->assign(RoleId::fromString('rol_aaaaaaaaaaaaaaaa'), $user, new DateTimeImmutable());
        $this->roles()->assign(RoleId::fromString('rol_bbbbbbbbbbbbbbbb'), $user, new DateTimeImmutable());

        self::assertSame(
            'invoices:read invoices:write',
            $this->roles()->permissionsHeld($user, $invoices->id)->toString(),
        );
        self::assertSame('export', $this->roles()->permissionsHeld($user, $reports->id)->toString());
        self::assertTrue($this->roles()->permissionsHeld($other, $invoices->id)->isEmpty());
    }

    #[Test]
    public function aDeletedRoleOrAccountLeavesNoAssignment(): void
    {
        $api = $this->invoicesApi();
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Reader', [[$api, 'invoices:read']]);
        $kept = $this->aRole('rol_bbbbbbbbbbbbbbbb', 'Kept', [[$api, 'invoices:read']]);
        $this->roles()->save($role);
        $this->roles()->save($kept);
        $jane = $this->aRoleHolder('jane@example.com');
        $john = $this->aRoleHolder('john@example.com');
        $this->roles()->assign($role->id, $jane, new DateTimeImmutable());
        $this->roles()->assign($kept->id, $john, new DateTimeImmutable());

        $this->roles()->delete($role->id);
        $this->users()->delete($john);

        self::assertNull($this->roles()->find($role->id));
        self::assertSame([], $this->roles()->rolesOf($jane));
        self::assertTrue($this->roles()->permissionsHeld($jane, $api->id)->isEmpty());
        self::assertSame(0, $this->roles()->holders($kept->id, PageRequest::of())->total);
    }

    #[Test]
    public function aGroupTakesBackOnlyTheRoleItGave(): void
    {
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Support', []);
        $this->roles()->save($role);
        $jane = $this->aRoleHolder('jane@example.com');
        $john = $this->aRoleHolder('john@example.com');
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');

        self::assertTrue($this->roles()->grantThroughGroup($role->id, $jane, $at));
        self::assertFalse($this->roles()->grantThroughGroup($role->id, $jane, $at), 'Held already.');
        self::assertSame([$role->id->value], array_map(
            static fn (RoleId $id): string => $id->value,
            $this->roles()->rolesThroughGroups($jane),
        ));
        self::assertTrue($this->roles()->withdrawGroupGrant($role->id, $jane));
        self::assertSame([], $this->roles()->rolesOf($jane));

        $this->roles()->assign($role->id, $john, $at);
        self::assertFalse($this->roles()->grantThroughGroup($role->id, $john, $at), 'Given by hand.');
        self::assertFalse($this->roles()->withdrawGroupGrant($role->id, $john), 'A group takes back only its own.');
        self::assertSame(['Support'], $this->roleNames($this->roles()->rolesOf($john)));
        self::assertSame([], $this->roles()->rolesThroughGroups($john));

        self::assertTrue($this->roles()->grantThroughGroup($role->id, $jane, $at));
        $this->roles()->assign($role->id, $jane, $at);
        self::assertSame([], $this->roles()->rolesThroughGroups($jane), 'Given by hand as well: by hand now.');
        self::assertFalse($this->roles()->withdrawGroupGrant($role->id, $jane));
    }

    #[Test]
    public function aProvisionableRoleIsReadBackSo(): void
    {
        $api = $this->invoicesApi();
        $role = $this->aRole('rol_aaaaaaaaaaaaaaaa', 'Billing', [[$api, 'invoices:read']])->withProvisionable(true);

        $this->roles()->save($role);

        self::assertTrue($this->roles()->find($role->id)?->provisionable);
        self::assertFalse($this->roles()->find($role->id)?->permissions[0]->onSystemApi);
    }

    private function invoicesApi(): ResourceServer
    {
        $api = $this->anApiWithRoles(
            'rs_invoices00000001',
            'https://invoices.example/api/',
            ['invoices:read', 'invoices:write'],
        );
        $this->resourceServers()->save($api);

        return $api;
    }

    /**
     * @param list<string> $permissions
     */
    private function anApiWithRoles(string $id, string $identifier, array $permissions): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString($id),
            Audience::fromString($identifier),
            'API',
            array_map(static fn (string $value): Permission => Permission::of($value), $permissions),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }

    /**
     * @param list<array{ResourceServer, string}> $grants
     */
    private function aRole(
        string $id,
        string $name,
        array $grants,
        string $description = 'Bills people',
        string $createdAt = '2026-01-15T10:00:00Z',
    ): Role {
        return Role::define(
            RoleId::fromString($id),
            $name,
            $description,
            array_map(
                static fn (array $grant): GrantedPermission => new GrantedPermission(
                    $grant[0]->id,
                    Scope::fromString($grant[1]),
                ),
                $grants,
            ),
            new DateTimeImmutable($createdAt),
        );
    }

    private function aRoleHolder(string $email): UserId
    {
        $id = UserId::fromString(sprintf('%08x-0000-4000-8000-000000000000', crc32($email)));
        $this->users()->save(User::register($id, $email, null, new DateTimeImmutable('2026-01-15T10:00:00Z')));

        return $id;
    }
}
