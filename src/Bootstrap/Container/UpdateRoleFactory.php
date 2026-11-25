<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Roles\RolePermissions;
use Clavia\Application\Management\Roles\UpdateRole;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Provisioning\Groups\GroupRoles;
use Clavia\Domain\Rbac\RoleRepository;
use Psr\Container\ContainerInterface;

final class UpdateRoleFactory
{
    public function __invoke(ContainerInterface $container): UpdateRole
    {
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var RolePermissions $permissions */
        $permissions = $container->get(RolePermissions::class);
        /** @var GroupRoles $groupRoles */
        $groupRoles = $container->get(GroupRoles::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new UpdateRole($roles, $permissions, $groupRoles, $events);
    }
}
