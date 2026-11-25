<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class SamlServiceProviderEndpointsFactory
{
    public function __invoke(ContainerInterface $container): SamlServiceProviderEndpoints
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $issuer = $settings->issuerUrl;
        assert($issuer !== '');

        return new SamlServiceProviderEndpoints($issuer);
    }
}
