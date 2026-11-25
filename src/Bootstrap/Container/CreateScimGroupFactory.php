<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Provisioning\Groups\CreateScimGroup;
use Clavia\Application\Provisioning\Groups\GroupMembers;
use Clavia\Application\Provisioning\Groups\GroupRoles;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class CreateScimGroupFactory
{
    public function __invoke(ContainerInterface $container): CreateScimGroup
    {
        /** @var ScimGroupRepository $groups */
        $groups = $container->get(ScimGroupRepository::class);
        /** @var GroupMembers $members */
        $members = $container->get(GroupMembers::class);
        /** @var GroupRoles $roles */
        $roles = $container->get(GroupRoles::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new CreateScimGroup($groups, $members, $roles, $transactions, $random, $clock);
    }
}
