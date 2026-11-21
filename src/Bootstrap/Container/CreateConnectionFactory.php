<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Connections\CreateConnection;
use Clavia\Application\Management\Connections\OidcConfiguration;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class CreateConnectionFactory
{
    public function __invoke(ContainerInterface $container): CreateConnection
    {
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var OidcConfiguration $oidc */
        $oidc = $container->get(OidcConfiguration::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new CreateConnection($connections, $oidc, $clock, $events);
    }
}
