<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class AssignRoleFactory
{
    public function __invoke(ContainerInterface $container): AssignRole
    {
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new AssignRole($roles, $users, $clock);
    }
}
