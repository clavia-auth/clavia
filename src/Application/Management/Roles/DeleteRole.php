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
use Clavia\Domain\Rbac\Event\RoleDeleted;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;

/**
 * `DELETE /api/v1/roles/{role_id}`: delete a role and every assignment of it. Its holders
 * lose what it granted at their next token.
 */
final readonly class DeleteRole
{
    public function __construct(
        private RoleRepository $roles,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     */
    public function __invoke(RoleId $id): void
    {
        $role = $this->roles->find($id) ?? throw NotFound::of('role');

        $this->roles->delete($id);
        $this->events->dispatch(new RoleDeleted($role));
    }
}
