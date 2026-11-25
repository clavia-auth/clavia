<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Provisioning\Groups\GroupRoles;
use Clavia\Domain\Rbac\Event\RoleChanged;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/roles/{role_id}`: rename a role, describe it, or replace what it grants.
 *
 * Takes effect on the next token each holder obtains: roles are read at issuance, never
 * trusted from a token or a code. Renaming it, or making it provisionable or not, works out again the
 * roles of everyone a SCIM group of either name reaches ({@see GroupRoles}).
 */
final readonly class UpdateRole
{
    public function __construct(
        private RoleRepository $roles,
        private RolePermissions $permissions,
        private GroupRoles $groupRoles,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws InvalidValue
     * @throws AlreadyExists When another role has the new name.
     */
    public function __invoke(RoleId $id, RoleChanges $changes): Role
    {
        $role = $this->roles->find($id) ?? throw NotFound::of('role');
        $before = $role;

        if ($changes->name !== null) {
            $role = $role->renamed($changes->name);
        }
        if ($changes->description !== null) {
            $role = $role->described($changes->description);
        }
        if ($changes->permissions !== null) {
            $role = $role->granting($this->permissions->resolve($changes->permissions));
        }
        if ($changes->provisionable !== null) {
            $role = $role->withProvisionable($changes->provisionable);
        }
        $this->roles->save($role);
        $this->events->dispatch(new RoleChanged($role->id, array_keys(array_filter([
            'name' => $changes->name !== null,
            'description' => $changes->description !== null,
            'permissions' => $changes->permissions !== null,
            'provisionable' => $changes->provisionable !== null,
        ]))));
        // The groups that named it, and those that name it now, give it or take it back accordingly.
        if ($role->name !== $before->name || $role->provisionable !== $before->provisionable) {
            $this->groupRoles->reconcileNamed($before->name, $role->name);
        }

        return $role;
    }
}
