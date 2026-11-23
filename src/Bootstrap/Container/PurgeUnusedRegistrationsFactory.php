<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Clients\Registration\PurgeUnusedRegistrations;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class PurgeUnusedRegistrationsFactory
{
    public function __invoke(ContainerInterface $container): PurgeUnusedRegistrations
    {
        /** @var ClientRegistrationRepository $registrations */
        $registrations = $container->get(ClientRegistrationRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $lifetime = $settings->clientRegistrationUnusedLifetime;
        assert($lifetime > 0);

        return new PurgeUnusedRegistrations($registrations, $clients, $transactions, $clock, $events, $lifetime);
    }
}
