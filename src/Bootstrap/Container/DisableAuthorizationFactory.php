<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\ResourceServers\DisableAuthorization;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Psr\Container\ContainerInterface;

final class DisableAuthorizationFactory
{
    public function __invoke(ContainerInterface $container): DisableAuthorization
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var DecisionEngine $engine */
        $engine = $container->get(DecisionEngine::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new DisableAuthorization($resourceServers, $engine, $transactions, $events);
    }
}
