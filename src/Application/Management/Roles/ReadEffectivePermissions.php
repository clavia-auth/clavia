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
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;

/**
 * `GET /api/v1/users/{user_id}/permissions`: everything somebody holds, on every API, and
 * which of their roles grant each — the answer to "why can they do that?".
 */
final readonly class ReadEffectivePermissions
{
    public function __construct(
        private RoleRepository $roles,
        private UserRepository $users,
        private RolePermissions $permissions,
    ) {
    }

    /**
     * @return list<EffectivePermission> By API identifier, then value.
     *
     * @throws NotFound
     */
    public function __invoke(UserId $user): array
    {
        if ($this->users->find($user) === null) {
            throw NotFound::of('user');
        }

        /** @var array<string, DescribedPermission> $permissions */
        $permissions = [];
        /** @var array<string, non-empty-list<Role>> $grantedBy */
        $grantedBy = [];
        foreach ($this->roles->rolesOf($user) as $role) {
            foreach ($this->permissions->describe($role->permissions) as $permission) {
                $key = $permission->resourceServerId->value . ' ' . $permission->value;
                $permissions[$key] = $permission;
                $grantedBy[$key] = [...($grantedBy[$key] ?? []), $role];
            }
        }

        $effective = [];
        foreach ($permissions as $key => $permission) {
            $effective[] = new EffectivePermission($permission, $grantedBy[$key]);
        }
        usort($effective, static function (EffectivePermission $a, EffectivePermission $b): int {
            return RolePermissions::compare($a->permission, $b->permission);
        });

        return $effective;
    }
}
