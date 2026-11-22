<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\ConfirmEmail;
use Clavia\Application\Port\AccountLinkStore;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ConfirmEmailFactory
{
    public function __invoke(ContainerInterface $container): ConfirmEmail
    {
        /** @var AccountLinkStore $links */
        $links = $container->get(AccountLinkStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new ConfirmEmail(
            $links,
            $users,
            $loginStates,
            $transactions,
            $events,
            $clock,
        );
    }
}
