<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\RequestPasswordReset;
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class RequestPasswordResetFactory
{
    public function __invoke(ContainerInterface $container): RequestPasswordReset
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var SendAccountLink $links */
        $links = $container->get(SendAccountLink::class);

        return new RequestPasswordReset(
            $access,
            $clients,
            $loginStates,
            $users,
            $links,
        );
    }
}
