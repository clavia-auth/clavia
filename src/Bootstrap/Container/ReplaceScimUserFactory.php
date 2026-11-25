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
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Application\Provisioning\Users\ReplaceScimUser;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ReplaceScimUserFactory
{
    public function __invoke(ContainerInterface $container): ReplaceScimUser
    {
        /** @var ReadScimUsers $read */
        $read = $container->get(ReadScimUsers::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ProvisionedAccountRepository $accounts */
        $accounts = $container->get(ProvisionedAccountRepository::class);
        /** @var ExternalIdentityRepository $identities */
        $identities = $container->get(ExternalIdentityRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var SignOutEverywhere $signOut */
        $signOut = $container->get(SignOutEverywhere::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new ReplaceScimUser($read, $users, $accounts, $identities, $transactions, $signOut, $clock, $events);
    }
}
