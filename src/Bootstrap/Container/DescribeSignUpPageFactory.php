<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\DescribeSignUpPage;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class DescribeSignUpPageFactory
{
    public function __invoke(ContainerInterface $container): DescribeSignUpPage
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var DescribeLoginPage $loginPage */
        $loginPage = $container->get(DescribeLoginPage::class);

        return new DescribeSignUpPage(
            $access,
            $loginStates,
            $clients,
            $loginPage,
        );
    }
}
