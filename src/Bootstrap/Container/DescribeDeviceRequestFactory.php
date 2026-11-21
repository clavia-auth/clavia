<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Device\DescribeDeviceRequest;
use Clavia\Application\OAuth2\Device\PendingDeviceRequests;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\ScopeSet;
use Psr\Container\ContainerInterface;

final class DescribeDeviceRequestFactory
{
    public function __invoke(ContainerInterface $container): DescribeDeviceRequest
    {
        /** @var PendingDeviceRequests $pending */
        $pending = $container->get(PendingDeviceRequests::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new DescribeDeviceRequest(
            $pending,
            $users,
            $resourceServers,
            ScopeSet::fromString(implode(' ', $settings->scopesSupported)),
        );
    }
}
