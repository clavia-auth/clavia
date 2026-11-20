<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * Roles in memory, honouring the foreign keys PostgreSQL enforces: given the APIs and the
 * accounts, a permission an API no longer defines is granted by no role, and a deleted
 * account holds nothing — applied as the data is read, which is when it shows.
 */
final class InMemoryRoleRepository implements RoleRepository
{
    /** @var array<string, Role> By id. */
    private array $roles = [];

    /** @var array<string, array<string, DateTimeImmutable>> When each role was assigned, by user id then role id. */
    private array $assignments = [];

    public function __construct(
        private readonly ?InMemoryResourceServerRepository $resourceServers = null,
        private readonly ?InMemoryUserRepository $users = null,
    ) {
    }

    #[\Override]
    public function find(RoleId $id): ?Role
    {
        $role = $this->roles[$id->value] ?? null;

        return $role === null ? null : $this->current($role);
    }

    #[\Override]
    public function findByName(string $name): ?Role
    {
        foreach ($this->roles as $role) {
            if ($role->name === $name) {
                return $this->current($role);
            }
        }

        return null;
    }

    #[\Override]
    public function save(Role $role): void
    {
        $other = $this->findByName($role->name);
        if ($other !== null && ! $other->id->equals($role->id)) {
            throw new AlreadyExists(sprintf("A role named '%s' already exists.", $role->name));
        }

        $this->roles[$role->id->value] = $role;
    }

    #[\Override]
    public function delete(RoleId $id): void
    {
        unset($this->roles[$id->value]);
        foreach (array_keys($this->assignments) as $user) {
            unset($this->assignments[$user][$id->value]);
        }
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        return InMemoryPaging::page(
            array_map($this->current(...), array_values($this->roles)),
            $request,
            static fn (Role $role): array => [$role->name, $role->description],
            static fn (Role $role): array => [$role->createdAt, $role->id->value],
        );
    }

    #[\Override]
    public function all(): array
    {
        $roles = array_map($this->current(...), array_values($this->roles));
        usort($roles, static fn (Role $a, Role $b): int => strcmp($a->name, $b->name));

        return $roles;
    }

    #[\Override]
    public function assign(RoleId $role, UserId $user, DateTimeImmutable $at): void
    {
        $this->assignments[$user->value][$role->value] ??= $at;
    }

    #[\Override]
    public function unassign(RoleId $role, UserId $user): void
    {
        unset($this->assignments[$user->value][$role->value]);
    }

    #[\Override]
    public function replaceRolesOf(UserId $user, array $roles, DateTimeImmutable $at): void
    {
        $kept = [];
        foreach ($roles as $role) {
            $kept[$role->value] = $this->assignments[$user->value][$role->value] ?? $at;
        }
        $this->assignments[$user->value] = $kept;
    }

    #[\Override]
    public function rolesOf(UserId $user): array
    {
        if (! $this->exists($user)) {
            return [];
        }

        $roles = [];
        foreach (array_keys($this->assignments[$user->value] ?? []) as $id) {
            $role = $this->find(RoleId::fromString($id));
            if ($role !== null) {
                $roles[] = $role;
            }
        }
        usort($roles, static fn (Role $a, Role $b): int => strcmp($a->name, $b->name));

        return $roles;
    }

    #[\Override]
    public function holders(RoleId $role, PageRequest $request): Page
    {
        /** @var list<array{UserId, DateTimeImmutable}> $holders */
        $holders = [];
        foreach ($this->assignments as $user => $roles) {
            $userId = UserId::fromString($user);
            if (isset($roles[$role->value], $this->roles[$role->value]) && $this->exists($userId)) {
                $holders[] = [$userId, $roles[$role->value]];
            }
        }
        // Most recently assigned first; among equals, by user id.
        usort($holders, static fn (array $a, array $b): int => [$b[1], $a[0]->value] <=> [$a[1], $b[0]->value]);
        $ids = array_map(static fn (array $holder): UserId => $holder[0], $holders);

        return new Page(array_slice($ids, $request->offset(), $request->perPage), count($ids), $request);
    }

    #[\Override]
    public function permissionsHeld(UserId $user, ResourceServerId $resourceServer): ScopeSet
    {
        $held = ScopeSet::empty();
        foreach ($this->rolesOf($user) as $role) {
            $held = $held->union($role->grantsOn($resourceServer));
        }

        return $held;
    }

    /** The role as storage would show it: without a permission its API no longer defines. */
    private function current(Role $role): Role
    {
        $resourceServers = $this->resourceServers;
        if ($resourceServers === null) {
            return $role;
        }

        $defined = static function (GrantedPermission $granted) use ($resourceServers): bool {
            return $resourceServers->find($granted->resourceServerId)?->defines($granted->value) === true;
        };

        return $role->granting(array_values(array_filter($role->permissions, $defined)));
    }

    private function exists(UserId $user): bool
    {
        return $this->users === null || $this->users->find($user) !== null;
    }
}
