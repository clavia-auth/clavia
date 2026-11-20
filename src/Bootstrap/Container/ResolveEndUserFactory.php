<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\DevelopmentAutoLogin;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class ResolveEndUserFactory
{
    public function __invoke(ContainerInterface $container): ResolveEndUser
    {
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var DevelopmentAutoLogin $autoLogin */
        $autoLogin = $container->get(DevelopmentAutoLogin::class);

        return new ResolveEndUser($sessions, $users, $autoLogin);
    }
}
