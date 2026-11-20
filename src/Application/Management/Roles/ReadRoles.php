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
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/roles` and `GET /api/v1/roles/{role_id}`.
 */
final readonly class ReadRoles
{
    public function __construct(
        private RoleRepository $roles,
        private RolePermissions $permissions,
    ) {
    }

    /**
     * @return Page<Role>
     */
    public function page(PageRequest $request): Page
    {
        return $this->roles->page($request);
    }

    /**
     * Every role, by name: for the shell.
     *
     * @return list<Role>
     */
    public function all(): array
    {
        return $this->roles->all();
    }

    /**
     * @throws NotFound
     */
    public function one(RoleId $id): DescribedRole
    {
        return $this->describe($this->roles->find($id) ?? throw NotFound::of('role'));
    }

    public function describe(Role $role): DescribedRole
    {
        return new DescribedRole($role, $this->permissions->describe($role->permissions));
    }
}
