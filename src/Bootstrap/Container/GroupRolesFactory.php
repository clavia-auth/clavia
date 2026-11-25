<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Provisioning\Groups\GroupRoles;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class GroupRolesFactory
{
    public function __invoke(ContainerInterface $container): GroupRoles
    {
        /** @var ScimGroupRepository $groups */
        $groups = $container->get(ScimGroupRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new GroupRoles($groups, $roles, $clock, $events);
    }
}
