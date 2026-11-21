<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\Event\RoleGiven;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Give somebody a role, both named as a person at a shell names them: `clavia
 * roles:assign`. The other half of {@see EnsureRole}'s bootstrap — until somebody holds
 * a role with `read:users`, the dashboard has nothing to show them and no way to fix that
 * through itself.
 */
final readonly class AssignRole
{
    public function __construct(
        private RoleRepository $roles,
        private UserRepository $users,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param string $email The address the account was registered with, exactly.
     *
     * @return list<Role> Every role the account holds now, by name.
     *
     * @throws NotFound When there is no such role or account.
     */
    public function __invoke(string $roleName, string $email): array
    {
        $role = $this->roles->findByName($roleName) ?? throw NotFound::of('role');
        $user = $this->users->findByEmail(ConnectionName::defaultPool(), $email) ?? throw NotFound::of('user');

        $held = array_any($this->roles->rolesOf($user->id), static fn (Role $one): bool => $one->id->equals($role->id));
        if (! $held) {
            $this->roles->assign($role->id, $user->id, $this->clock->now());
            $this->events->dispatch(new RoleGiven($role->id, $user->id));
        }

        return $this->roles->rolesOf($user->id);
    }
}
