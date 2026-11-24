<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class SignInWithPasswordFactory
{
    public function __invoke(ContainerInterface $container): SignInWithPassword
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var LoginThrottle $throttle */
        $throttle = $container->get(LoginThrottle::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var SendAccountLink $verificationLinks */
        $verificationLinks = $container->get(SendAccountLink::class);

        return new SignInWithPassword(
            $users,
            $hasher,
            $throttle,
            $loginStates,
            $clients,
            $access,
            $completeFirstFactor,
            $events,
            $verificationLinks,
            $clock,
        );
    }
}
