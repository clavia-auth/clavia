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
use Clavia\Application\Management\Users\ManagedUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * `GET /api/v1/roles/{role_id}/users`: who holds a role, most recently given first.
 */
final readonly class ReadRoleHolders
{
    public function __construct(
        private RoleRepository $roles,
        private UserRepository $users,
        private ReadUsers $readUsers,
    ) {
    }

    /**
     * @return Page<ManagedUser>
     *
     * @throws NotFound
     */
    public function __invoke(RoleId $role, PageRequest $request): Page
    {
        if ($this->roles->find($role) === null) {
            throw NotFound::of('role');
        }

        $holders = $this->roles->holders($role, $request);
        $users = [];
        foreach ($holders->items as $id) {
            // An account deleted since the page was read takes its assignment with it.
            $user = $this->users->find($id);
            if ($user instanceof User) {
                $users[] = $user;
            }
        }

        return new Page($this->readUsers->describeAll($users), $holders->total, $holders->request);
    }
}
