<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class DescribeLoginPageFactory
{
    public function __invoke(ContainerInterface $container): DescribeLoginPage
    {
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);

        return new DescribeLoginPage($loginStates, $clients, $resolveEndUser, $users);
    }
}
