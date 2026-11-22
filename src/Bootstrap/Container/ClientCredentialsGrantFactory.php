<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\AccessTokenMinter;
use Clavia\Application\OAuth2\Token\ClientCredentialsGrant;
use Clavia\Application\Port\DomainEvents;
use Clavia\Configuration\Settings;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ClientCredentialsGrantFactory
{
    public function __invoke(ContainerInterface $container): ClientCredentialsGrant
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var ClientGrantRepository $clientGrants */
        $clientGrants = $container->get(ClientGrantRepository::class);
        /** @var AccessTokenMinter $accessTokens */
        $accessTokens = $container->get(AccessTokenMinter::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $lifetime = $settings->accessTokenLifetime;
        assert($lifetime > 0);

        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new ClientCredentialsGrant(
            $resourceServers,
            $clientGrants,
            $accessTokens,
            $clock,
            $lifetime,
            $events,
        );
    }
}
