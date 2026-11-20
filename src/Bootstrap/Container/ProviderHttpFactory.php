<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\IdentityProvider\ProviderHttp;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

final class ProviderHttpFactory
{
    public function __invoke(ContainerInterface $container): ProviderHttp
    {
        /** @var ClientInterface $client */
        $client = $container->get(ClientInterface::class);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new ProviderHttp($client, $requests, $streams, $logger);
    }
}
