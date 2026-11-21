<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Application\Management\Roles\CreateRole;
use Clavia\Application\Management\Roles\DeleteRole;
use Clavia\Application\Management\Roles\DescribedPermission;
use Clavia\Application\Management\Roles\EffectivePermission;
use Clavia\Application\Management\Roles\NewRole;
use Clavia\Application\Management\Roles\PermissionReference;
use Clavia\Application\Management\Roles\ReadEffectivePermissions;
use Clavia\Application\Management\Roles\ReadRoleHolders;
use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\RoleAssignments;
use Clavia\Application\Management\Roles\RoleChanges;
use Clavia\Application\Management\Roles\RolePermissions;
use Clavia\Application\Management\Roles\UpdateRole;
use Clavia\Application\Management\Users\ManagedUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Roles through the Management API's use cases, and the two of the shell.
 */
final class RolesTest extends TestCase
{
    private const string INVOICES = 'https://invoices.test/api/';
    private const string REPORTS = 'https://reports.test/api/';

    private InMemoryResourceServerRepository $apis;
    private InMemoryUserRepository $users;
    private InMemoryRoleRepository $roles;
    private InMemoryTransactionManager $transactions;
    private FrozenClock $clock;
    private SecretGenerator $secrets;
    private ResourceServer $invoices;
    private ResourceServer $reports;

    #[\Override]
    protected function setUp(): void
    {
        $this->apis = new InMemoryResourceServerRepository();
        $this->users = new InMemoryUserRepository();
        $this->roles = new InMemoryRoleRepository($this->apis, $this->users);
        $this->transactions = new InMemoryTransactionManager();
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->secrets = new SecretGenerator(new SeededRandomSource(1));
        $this->invoices = $this->api('rs_invoices00000001', self::INVOICES, [
            'invoices:read' => 'Read invoices',
            'invoices:write' => 'Write invoices',
        ]);
        $this->reports = $this->api('rs_reports000000001', self::REPORTS, ['export' => 'Export reports']);
    }

    // ── Defining ────────────────────────────────────────────────────────────────

    public function testARoleIsDefinedWithThePermissionsItNamesDescribedFromTheirApis(): void
    {
        $role = $this->create('Billing', [
            $this->reference($this->reports, 'export'),
            $this->reference($this->invoices, 'invoices:read'),
            $this->reference($this->invoices, 'invoices:read'),
        ]);

        $described = $this->read()->one($role->id);

        self::assertStringStartsWith('rol_', $role->id->value);
        self::assertSame(
            [
                [self::INVOICES, 'invoices:read', 'Read invoices'],
                [self::REPORTS, 'export', 'Export reports'],
            ],
            array_map(
                static fn (DescribedPermission $permission): array => [
                    $permission->resourceServerIdentifier->value,
                    $permission->value,
                    $permission->description,
                ],
                $described->permissions,
            ),
        );
    }

    /**
     * @param array{string, string} $reference
     */
    #[DataProvider('undefinedPermissions')]
    public function testARoleCannotGrantWhatNoApiDefines(array $reference): void
    {
        $this->expectException(InvalidValue::class);

        $this->create('Ghost', [new PermissionReference(...$reference)]);
    }

    /** @return iterable<string, array{array{string, string}}> */
    public static function undefinedPermissions(): iterable
    {
        yield 'a value the API does not define' => [['rs_invoices00000001', 'invoices:delete']];
        yield 'an API that does not exist' => [['rs_nowhere000000001', 'invoices:read']];
        yield 'not an API id at all' => [['invoices', 'invoices:read']];
        yield 'not a scope token' => [['rs_invoices00000001', 'has space']];
    }

    public function testARoleNameIsTakenOnce(): void
    {
        $this->create('Billing', []);

        $this->expectException(AlreadyExists::class);
        $this->create('Billing', []);
    }

    public function testAnUpdateChangesOnlyWhatItNames(): void
    {
        $role = $this->create('Billing', [$this->reference($this->invoices, 'invoices:read')]);
        $update = new UpdateRole($this->roles, $this->permissions(), new InMemoryDomainEvents());

        $renamed = $update($role->id, new RoleChanges(name: 'Accounts'));
        self::assertSame('Accounts', $renamed->name);
        self::assertSame('invoices:read', $renamed->grantsOn($this->invoices->id)->toString());

        $regranted = $update($role->id, new RoleChanges(permissions: [$this->reference($this->reports, 'export')]));
        self::assertSame('Accounts', $regranted->name);
        self::assertTrue($regranted->grantsOn($this->invoices->id)->isEmpty());
        self::assertSame('export', $this->roles->find($role->id)?->grantsOn($this->reports->id)->toString());

        $this->expectException(NotFound::class);
        $update(RoleId::fromString('rol_zzzzzzzzzzzzzzzz'), new RoleChanges(name: 'X'));
    }

    public function testDeletingARoleThatDoesNotExistIsNotFound(): void
    {
        $role = $this->create('Billing', []);
        $delete = new DeleteRole($this->roles, new InMemoryDomainEvents());

        $delete($role->id);
        self::assertNull($this->roles->find($role->id));

        $this->expectException(NotFound::class);
        $delete($role->id);
    }

    // ── Holding ─────────────────────────────────────────────────────────────────

    public function testGivingARoleIsRefusedWholeWhenAnAccountDoesNotExist(): void
    {
        $role = $this->create('Billing', []);
        $jane = $this->user('jane@example.com');

        try {
            $this->assignments()->give($role->id, [$jane->id, UserId::generate(new SeededRandomSource(99))]);
            self::fail('A role was given to an account that does not exist.');
        } catch (NotFound) {
            self::assertSame([], $this->roles->rolesOf($jane->id));
        }

        $this->assignments()->give($role->id, [$jane->id]);
        self::assertSame(['Billing'], self::names($this->assignments()->rolesOf($jane->id)));

        $this->assignments()->take($role->id, $jane->id);
        $this->assignments()->take($role->id, $jane->id);
        self::assertSame([], $this->assignments()->rolesOf($jane->id));
    }

    public function testSettingSomebodysRolesIsRefusedWholeWhenARoleDoesNotExist(): void
    {
        $a = $this->create('A', []);
        $b = $this->create('B', []);
        $jane = $this->user('jane@example.com');
        $this->assignments()->give($a->id, [$jane->id]);

        try {
            $this->assignments()->replaceRolesOf($jane->id, [$b->id, RoleId::fromString('rol_zzzzzzzzzzzzzzzz')]);
            self::fail('Roles were set that do not exist.');
        } catch (NotFound) {
            self::assertSame(['A'], self::names($this->roles->rolesOf($jane->id)));
        }

        self::assertSame(['B'], self::names($this->assignments()->replaceRolesOf($jane->id, [$b->id])));
    }

    public function testAnAccountThatDoesNotExistHasNoRolesToShow(): void
    {
        $this->expectException(NotFound::class);

        $this->assignments()->rolesOf(UserId::generate(new SeededRandomSource(99)));
    }

    public function testTheHoldersOfARoleAreShownAsAccounts(): void
    {
        $role = $this->create('Billing', []);
        $jane = $this->user('jane@example.com');
        $john = $this->user('john@example.com');
        $this->roles->assign($role->id, $jane->id, new DateTimeImmutable('2026-01-15T10:00:00Z'));
        $this->roles->assign($role->id, $john->id, new DateTimeImmutable('2026-01-15T11:00:00Z'));
        $holders = new ReadRoleHolders(
            $this->roles,
            $this->users,
            new ReadUsers($this->users, new InMemoryMfaFactorRepository($this->transactions)),
        );

        $page = $holders($role->id, PageRequest::of());

        self::assertSame(2, $page->total);
        self::assertSame(
            ['john@example.com', 'jane@example.com'],
            array_map(static fn (ManagedUser $managed): string => $managed->user->email, $page->items),
        );

        $this->expectException(NotFound::class);
        $holders(RoleId::fromString('rol_zzzzzzzzzzzzzzzz'), PageRequest::of());
    }

    public function testEveryPermissionSomebodyHoldsNamesEachRoleThatGrantsIt(): void
    {
        $jane = $this->user('jane@example.com');
        $reader = $this->create('Reader', [$this->reference($this->invoices, 'invoices:read')]);
        $billing = $this->create('Billing', [
            $this->reference($this->invoices, 'invoices:read'),
            $this->reference($this->reports, 'export'),
        ]);
        $this->assignments()->give($reader->id, [$jane->id]);
        $this->assignments()->give($billing->id, [$jane->id]);

        $effective = (new ReadEffectivePermissions($this->roles, $this->users, $this->permissions()))($jane->id);

        self::assertSame(
            [
                [self::INVOICES, 'invoices:read', ['Billing', 'Reader']],
                [self::REPORTS, 'export', ['Billing']],
            ],
            array_map(
                static fn (EffectivePermission $held): array => [
                    $held->permission->resourceServerIdentifier->value,
                    $held->permission->value,
                    self::names($held->roles),
                ],
                $effective,
            ),
        );
    }

    // ── The shell ───────────────────────────────────────────────────────────────

    public function testEnsuringARoleAddsToItAndNeverTakesAway(): void
    {
        $ensure = new EnsureRole(
            $this->roles,
            $this->apis,
            $this->transactions,
            $this->secrets,
            $this->clock,
            new InMemoryDomainEvents(),
        );
        $audience = Audience::fromString(self::INVOICES);

        $first = $ensure('Billing', 'Bills people', $audience, ScopeSet::fromString('invoices:read'));
        $again = $ensure('Billing', 'Ignored', $audience, ScopeSet::fromString('invoices:write'));
        $everything = $ensure('Everything', '', $audience);

        self::assertSame($first->id->value, $again->id->value);
        self::assertSame('Bills people', $again->description);
        self::assertSame('invoices:read invoices:write', $again->grantsOn($this->invoices->id)->toString());
        self::assertSame('invoices:read invoices:write', $everything->grantsOn($this->invoices->id)->toString());
        self::assertCount(2, $this->roles->all());
    }

    public function testEnsuringARoleRefusesWhatTheApiDoesNotDefineOrAnApiThatIsNotThere(): void
    {
        $ensure = new EnsureRole(
            $this->roles,
            $this->apis,
            $this->transactions,
            $this->secrets,
            $this->clock,
            new InMemoryDomainEvents(),
        );

        try {
            $ensure('Billing', '', Audience::fromString(self::INVOICES), ScopeSet::fromString('invoices:delete'));
            self::fail('A role was made to grant what the API does not define.');
        } catch (InvalidValue $refusal) {
            self::assertStringContainsString('invoices:delete', $refusal->getMessage());
        }
        self::assertSame([], $this->roles->all());

        $this->expectException(NotFound::class);
        $ensure('Billing', '', Audience::fromString('https://nowhere.test/'));
    }

    public function testARoleIsGivenAtTheShellByNameAndAddress(): void
    {
        $this->create('Billing', []);
        $jane = $this->user('jane@example.com');
        $assign = new AssignRole($this->roles, $this->users, $this->clock, new InMemoryDomainEvents());

        self::assertSame(['Billing'], self::names($assign('Billing', 'jane@example.com')));
        self::assertSame(['Billing'], self::names($this->roles->rolesOf($jane->id)));

        $refused = [];
        foreach ([['Nobody', 'jane@example.com'], ['Billing', 'nobody@example.com']] as [$role, $email]) {
            try {
                $assign($role, $email);
            } catch (NotFound $refusal) {
                $refused[] = $refusal->getMessage();
            }
        }
        self::assertSame(['No such role.', 'No such user.'], $refused);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * @param list<PermissionReference> $permissions
     */
    private function create(string $name, array $permissions): Role
    {
        return (new CreateRole(
            $this->roles,
            $this->permissions(),
            $this->secrets,
            $this->clock,
            new InMemoryDomainEvents(),
        ))(
            new NewRole($name, '', $permissions),
        );
    }

    private function read(): ReadRoles
    {
        return new ReadRoles($this->roles, $this->permissions());
    }

    private function permissions(): RolePermissions
    {
        return new RolePermissions($this->apis);
    }

    private function assignments(): RoleAssignments
    {
        return new RoleAssignments(
            $this->roles,
            $this->users,
            $this->transactions,
            $this->clock,
            new InMemoryDomainEvents(),
        );
    }

    private function reference(ResourceServer $api, string $value): PermissionReference
    {
        return new PermissionReference($api->id->value, $value);
    }

    /**
     * @param array<string, string> $permissions Value → description.
     */
    private function api(string $id, string $identifier, array $permissions): ResourceServer
    {
        $permissionList = [];
        foreach ($permissions as $value => $description) {
            $permissionList[] = Permission::of($value, $description);
        }
        $api = ResourceServer::register(
            ResourceServerId::fromString($id),
            Audience::fromString($identifier),
            'API',
            $permissionList,
            $this->clock->now(),
        );
        $this->apis->save($api);

        return $api;
    }

    private function user(string $email): User
    {
        $user = User::register(
            UserId::fromString(sprintf('%08x-0000-4000-8000-000000000000', crc32($email))),
            $email,
            null,
            $this->clock->now(),
        );
        $this->users->save($user);

        return $user;
    }

    /**
     * @param list<Role> $roles
     *
     * @return list<string>
     */
    private static function names(array $roles): array
    {
        return array_map(static fn (Role $role): string => $role->name, $roles);
    }
}
