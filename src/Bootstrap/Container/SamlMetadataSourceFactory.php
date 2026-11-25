<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Saml\HttpSamlMetadataSource;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class SamlMetadataSourceFactory
{
    public function __invoke(ContainerInterface $container): SamlMetadataSource
    {
        /** @var ClientInterface $client */
        $client = $container->get(ClientInterface::class);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var OutboundUrlPolicy $outbound */
        $outbound = $container->get(OutboundUrlPolicy::class);

        return new HttpSamlMetadataSource($client, $requests, $outbound);
    }
}
