<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passwordless\FinishPasswordlessSignIn;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class FinishPasswordlessSignInFactory
{
    public function __invoke(ContainerInterface $container): FinishPasswordlessSignIn
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new FinishPasswordlessSignIn(
            $access,
            $clients,
            $users,
            $loginStates,
            $completeFirstFactor,
            $random,
            $clock,
        );
    }
}
