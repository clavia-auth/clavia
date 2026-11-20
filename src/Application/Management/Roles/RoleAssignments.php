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
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Who holds which role: `POST|DELETE /api/v1/roles/{role_id}/users…` from the role's
 * side, `GET|PUT /api/v1/users/{user_id}/roles` from the account's.
 *
 * Every change is idempotent — giving a role somebody holds, or taking one they do not,
 * changes nothing — and every one is refused whole when a role or account it names does
 * not exist, rather than applied in part.
 */
final readonly class RoleAssignments
{
    public function __construct(
        private RoleRepository $roles,
        private UserRepository $users,
        private TransactionManager $transactions,
        private Clock $clock,
    ) {
    }

    /**
     * @param list<UserId> $users
     *
     * @throws NotFound When the role or one of the accounts does not exist.
     */
    public function give(RoleId $role, array $users): void
    {
        $this->requireRole($role);
        foreach ($users as $user) {
            $this->requireUser($user);
        }

        $this->transactions->transactional(function () use ($role, $users): void {
            $now = $this->clock->now();
            foreach ($users as $user) {
                $this->roles->assign($role, $user, $now);
            }
        });
    }

    /**
     * @throws NotFound When the role or the account does not exist.
     */
    public function take(RoleId $role, UserId $user): void
    {
        $this->requireRole($role);
        $this->requireUser($user);

        $this->roles->unassign($role, $user);
    }

    /**
     * @return list<Role> By name.
     *
     * @throws NotFound
     */
    public function rolesOf(UserId $user): array
    {
        $this->requireUser($user);

        return $this->roles->rolesOf($user);
    }

    /**
     * Make the account hold exactly `$roles`.
     *
     * @param list<RoleId> $roles
     *
     * @return list<Role> What the account holds now, by name.
     *
     * @throws NotFound When the account or one of the roles does not exist.
     */
    public function replaceRolesOf(UserId $user, array $roles): array
    {
        $this->requireUser($user);
        foreach ($roles as $role) {
            $this->requireRole($role);
        }

        $this->roles->replaceRolesOf($user, $roles, $this->clock->now());

        return $this->roles->rolesOf($user);
    }

    /**
     * @throws NotFound
     */
    private function requireRole(RoleId $role): void
    {
        if ($this->roles->find($role) === null) {
            throw NotFound::of('role');
        }
    }

    /**
     * @throws NotFound
     */
    private function requireUser(UserId $user): void
    {
        if ($this->users->find($user) === null) {
            throw NotFound::of('user');
        }
    }
}
