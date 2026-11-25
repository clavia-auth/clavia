<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\Saml\DescribeSamlServiceProvider;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Domain\Connection\ConnectionRepository;
use Psr\Container\ContainerInterface;

final class DescribeSamlServiceProviderFactory
{
    public function __invoke(ContainerInterface $container): DescribeSamlServiceProvider
    {
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var ServiceProviderKeys $keys */
        $keys = $container->get(ServiceProviderKeys::class);
        /** @var SamlServiceProvider $saml */
        $saml = $container->get(SamlServiceProvider::class);
        /** @var SamlServiceProviderEndpoints $endpoints */
        $endpoints = $container->get(SamlServiceProviderEndpoints::class);

        return new DescribeSamlServiceProvider($connections, $keys, $saml, $endpoints);
    }
}
