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
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/roles/{role_id}`: rename a role, describe it, or replace what it grants.
 *
 * Takes effect on the next token each holder obtains: roles are read at issuance, never
 * trusted from a token or a code.
 */
final readonly class UpdateRole
{
    public function __construct(
        private RoleRepository $roles,
        private RolePermissions $permissions,
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

        if ($changes->name !== null) {
            $role = $role->renamed($changes->name);
        }
        if ($changes->description !== null) {
            $role = $role->described($changes->description);
        }
        if ($changes->permissions !== null) {
            $role = $role->granting($this->permissions->resolve($changes->permissions));
        }
        $this->roles->save($role);

        return $role;
    }
}
