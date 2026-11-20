<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/roles`: define a role, with the permissions it grants.
 */
final readonly class CreateRole
{
    public function __construct(
        private RoleRepository $roles,
        private RolePermissions $permissions,
        private SecretGenerator $secrets,
        private Clock $clock,
    ) {
    }

    /**
     * @throws InvalidValue  When the name or description is invalid, or a permission is not defined.
     * @throws AlreadyExists When another role has the name.
     */
    public function __invoke(NewRole $new): Role
    {
        $role = Role::define(
            RoleId::generate($this->secrets),
            $new->name,
            $new->description,
            $this->permissions->resolve($new->permissions),
            $this->clock->now(),
        );
        $this->roles->save($role);

        return $role;
    }
}
