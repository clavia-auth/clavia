<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\PasswordScreen;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class CreateUserFactory
{
    public function __invoke(ContainerInterface $container): CreateUser
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var PasswordScreen $passwords */
        $passwords = $container->get(PasswordScreen::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new CreateUser($users, $hasher, $passwords, $random, $clock, $connections, $events);
    }
}
