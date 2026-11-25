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
use Clavia\Application\Provisioning\Groups\DeleteScimGroup;
use Clavia\Application\Provisioning\Groups\GroupRoles;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Psr\Container\ContainerInterface;

final class DeleteScimGroupFactory
{
    public function __invoke(ContainerInterface $container): DeleteScimGroup
    {
        /** @var ReadScimGroups $read */
        $read = $container->get(ReadScimGroups::class);
        /** @var ScimGroupRepository $groups */
        $groups = $container->get(ScimGroupRepository::class);
        /** @var GroupRoles $roles */
        $roles = $container->get(GroupRoles::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);

        return new DeleteScimGroup($read, $groups, $roles, $transactions);
    }
}
