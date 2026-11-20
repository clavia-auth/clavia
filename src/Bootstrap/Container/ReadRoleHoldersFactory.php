<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Roles\ReadRoleHolders;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Psr\Container\ContainerInterface;

final class ReadRoleHoldersFactory
{
    public function __invoke(ContainerInterface $container): ReadRoleHolders
    {
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ReadUsers $readUsers */
        $readUsers = $container->get(ReadUsers::class);

        return new ReadRoleHolders($roles, $users, $readUsers);
    }
}
