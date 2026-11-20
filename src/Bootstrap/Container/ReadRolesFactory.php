<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\RolePermissions;
use Clavia\Domain\Rbac\RoleRepository;
use Psr\Container\ContainerInterface;

final class ReadRolesFactory
{
    public function __invoke(ContainerInterface $container): ReadRoles
    {
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var RolePermissions $permissions */
        $permissions = $container->get(RolePermissions::class);

        return new ReadRoles($roles, $permissions);
    }
}
