<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Clients\Registration\DeleteClientConfiguration;
use Clavia\Application\Clients\Registration\RegisteredClients;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class DeleteClientConfigurationFactory
{
    public function __invoke(ContainerInterface $container): DeleteClientConfiguration
    {
        /** @var RegisteredClients $registered */
        $registered = $container->get(RegisteredClients::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var AuditContext $audit */
        $audit = $container->get(AuditContext::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new DeleteClientConfiguration($registered, $clients, $transactions, $audit, $events);
    }
}
