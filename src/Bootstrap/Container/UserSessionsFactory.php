<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\Users\UserSessions;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class UserSessionsFactory
{
    public function __invoke(ContainerInterface $container): UserSessions
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var SignOutEverywhere $signOut */
        $signOut = $container->get(SignOutEverywhere::class);

        return new UserSessions($users, $clients, $sessions, $signOut);
    }
}
