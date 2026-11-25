<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class RotateServiceProviderKeysFactory
{
    public function __invoke(ContainerInterface $container): RotateServiceProviderKeys
    {
        /** @var ServiceProviderKeyStore $keys */
        $keys = $container->get(ServiceProviderKeyStore::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $overlap = $settings->samlKeyOverlapDays;
        assert($overlap > 0, 'Bounded by #[Range].');

        return new RotateServiceProviderKeys($keys, $transactions, $clock, $overlap, $events);
    }
}
