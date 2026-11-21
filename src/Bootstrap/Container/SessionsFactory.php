<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\SessionStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class SessionsFactory
{
    public function __invoke(ContainerInterface $container): Sessions
    {
        /** @var SessionStore $store */
        $store = $container->get(SessionStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $idle = $settings->sessionIdleLifetime;
        $absolute = $settings->sessionAbsoluteLifetime;
        assert($idle > 0 && $absolute > 0);

        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new Sessions($store, $secrets, $clock, $idle, $absolute, $events);
    }
}
