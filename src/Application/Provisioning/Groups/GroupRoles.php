<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Groups;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Rbac\Event\RoleGiven;
use Clavia\Domain\Rbac\Event\RoleTaken;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Clock;

/**
 * The roles a person holds through a directory's groups (docs/design/scim-provisioning.md §5.5),
 * worked out again after anything that can change them: a group's members or name, a group gone, a
 * role renamed or made provisionable or not.
 *
 * For each person: what their groups should give is every **provisionable** role named exactly as one
 * of their groups; what is granted and should not be is taken back, what should be and is not is
 * granted. A role given by hand is the operator's, never taken back here (it simply is not counted as
 * a group's). Each change is `RoleGiven` or `RoleTaken`, by whoever acted: the directory, or the
 * operator who renamed the role.
 */
final readonly class GroupRoles
{
    public function __construct(
        private ScimGroupRepository $groups,
        private RoleRepository $roles,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /** @param list<UserId> $people */
    public function reconcile(array $people): void
    {
        $now = $this->clock->now();
        $byName = [];
        $seen = [];
        foreach ($people as $person) {
            if (isset($seen[$person->value])) {
                continue;
            }
            $seen[$person->value] = true;
            /** @var array<string, RoleId> $wanted */
            $wanted = [];
            foreach ($this->groups->ofMember($person) as $group) {
                $role = $byName[$group->displayName] ??= $this->roles->findByName($group->displayName) ?? false;
                if ($role !== false && $role->provisionable) {
                    $wanted[$role->id->value] = $role->id;
                }
            }
            foreach ($this->roles->rolesThroughGroups($person) as $held) {
                if (! isset($wanted[$held->value]) && $this->roles->withdrawGroupGrant($held, $person)) {
                    $this->events->dispatch(new RoleTaken($held, $person));
                }
            }
            foreach ($wanted as $role) {
                if ($this->roles->grantThroughGroup($role, $person, $now)) {
                    $this->events->dispatch(new RoleGiven($role, $person));
                }
            }
        }
    }

    /**
     * Everyone a group of one of these names reaches, worked out again: after a role is renamed, or
     * made provisionable or not.
     */
    public function reconcileNamed(string ...$names): void
    {
        $people = [];
        foreach (array_unique($names) as $name) {
            foreach ($this->groups->named($name) as $group) {
                array_push($people, ...$group->members);
            }
        }
        $this->reconcile($people);
    }
}
