<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * The roles, and who holds them.
 *
 * Storage keeps both honest by itself: a role grants a permission through a foreign key
 * onto the API's permission, and holds a user through one onto the account, so a
 * permission an API stops defining leaves every role, and a deleted account or role
 * leaves every assignment. Nothing here can name what no longer exists.
 */
interface RoleRepository
{
    public function find(RoleId $id): ?Role;

    public function findByName(string $name): ?Role;

    /**
     * Create the role, or replace its name, description and permissions.
     *
     * @throws AlreadyExists When another role has the name.
     */
    public function save(Role $role): void;

    /** Remove the role, and with it every assignment of it. */
    public function delete(RoleId $id): void;

    /**
     * Roles newest first, searching the name and the description.
     *
     * @return Page<Role>
     */
    public function page(PageRequest $request): Page;

    /**
     * Every role, by name: for the shell, where there are few enough to print.
     *
     * @return list<Role>
     */
    public function all(): array;

    /**
     * Give the role to the user, by an operator's hand: a group that also grants it will not take it
     * away. Giving it again changes nothing but that.
     */
    public function assign(RoleId $role, UserId $user, DateTimeImmutable $at): void;

    /**
     * Take the role from the user, however it was given. Taking one they do not hold changes nothing.
     */
    public function unassign(RoleId $role, UserId $user): void;

    /**
     * Give the role to the user through a directory's group (docs/design/scim-provisioning.md §5.5),
     * unless they already hold it, by hand or through another group.
     *
     * @return bool Whether they hold it now and did not before.
     */
    public function grantThroughGroup(RoleId $role, UserId $user, DateTimeImmutable $at): bool;

    /**
     * Take back a role a group gave: one given by hand stays.
     *
     * @return bool Whether it was taken.
     */
    public function withdrawGroupGrant(RoleId $role, UserId $user): bool;

    /**
     * The roles the user holds through groups alone, not by hand.
     *
     * @return list<RoleId>
     */
    public function rolesThroughGroups(UserId $user): array;

    /**
     * Make the user hold exactly `$roles`, by hand. A role they keep keeps when it was assigned.
     *
     * @param list<RoleId> $roles
     */
    public function replaceRolesOf(UserId $user, array $roles, DateTimeImmutable $at): void;

    /**
     * The roles the user holds, by name.
     *
     * @return list<Role>
     */
    public function rolesOf(UserId $user): array;

    /**
     * Who holds the role, most recently assigned first.
     *
     * @return Page<UserId>
     */
    public function holders(RoleId $role, PageRequest $request): Page;

    /**
     * What the user holds on one API through all their roles together — the one
     * question issuance asks, because a token names one audience.
     */
    public function permissionsHeld(UserId $user, ResourceServerId $resourceServer): ScopeSet;
}
