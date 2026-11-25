<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\Saml\ListServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Psr\Container\ContainerInterface;

final class ListServiceProviderKeysFactory
{
    public function __invoke(ContainerInterface $container): ListServiceProviderKeys
    {
        /** @var ServiceProviderKeys $keys */
        $keys = $container->get(ServiceProviderKeys::class);

        return new ListServiceProviderKeys($keys);
    }
}
