<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\BackChannelLogoutRegistration;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class UpdateClientFactory
{
    public function __invoke(ContainerInterface $container): UpdateClient
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var BackChannelLogoutRegistration $backChannel */
        $backChannel = $container->get(BackChannelLogoutRegistration::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new UpdateClient($clients, $backChannel, $events);
    }
}
