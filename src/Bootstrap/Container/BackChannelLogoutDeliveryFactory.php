<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Http\HttpBackChannelLogoutDelivery;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

final class BackChannelLogoutDeliveryFactory
{
    public function __invoke(ContainerInterface $container): HttpBackChannelLogoutDelivery
    {
        /** @var ClientInterface $http */
        $http = $container->get(ClientInterface::class);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);
        /** @var OutboundUrlPolicy $policy */
        $policy = $container->get(OutboundUrlPolicy::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new HttpBackChannelLogoutDelivery($http, $requests, $streams, $policy, $logger);
    }
}
