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
use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\Account\SignUp;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class SignUpFactory
{
    public function __invoke(ContainerInterface $container): SignUp
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var PasswordScreen $passwords */
        $passwords = $container->get(PasswordScreen::class);
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var SendAccountLink $links */
        $links = $container->get(SendAccountLink::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $limit = $settings->signUpLimit;
        assert($limit > 0);

        return new SignUp(
            $access,
            $clients,
            $loginStates,
            $users,
            $hasher,
            $passwords,
            $counter,
            $links,
            $completeFirstFactor,
            $transactions,
            $events,
            $random,
            $clock,
            $limit,
        );
    }
}
