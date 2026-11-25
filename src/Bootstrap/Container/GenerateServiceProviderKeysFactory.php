<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\Saml\GenerateServiceProviderKeys;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class GenerateServiceProviderKeysFactory
{
    public function __invoke(ContainerInterface $container): GenerateServiceProviderKeys
    {
        /** @var ServiceProviderKeyStore $keys */
        $keys = $container->get(ServiceProviderKeyStore::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new GenerateServiceProviderKeys($keys, $transactions, $clock, $events);
    }
}
