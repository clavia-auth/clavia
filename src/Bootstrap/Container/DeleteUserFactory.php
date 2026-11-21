<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\SignOutEverywhere;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class DeleteUserFactory
{
    public function __invoke(ContainerInterface $container): DeleteUser
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var SignOutEverywhere $signOut */
        $signOut = $container->get(SignOutEverywhere::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new DeleteUser($users, $signOut, $events);
    }
}
