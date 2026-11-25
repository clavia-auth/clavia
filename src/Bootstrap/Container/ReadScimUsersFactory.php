<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Psr\Container\ContainerInterface;

final class ReadScimUsersFactory
{
    public function __invoke(ContainerInterface $container): ReadScimUsers
    {
        /** @var ProvisionedAccountRepository $accounts */
        $accounts = $container->get(ProvisionedAccountRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);

        return new ReadScimUsers($accounts, $users);
    }
}
