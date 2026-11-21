<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Connections\OidcConfiguration;
use Clavia\Application\Port\OidcDiscovery;
use Clavia\Application\Port\SecretCipher;
use Psr\Container\ContainerInterface;

final class OidcConfigurationFactory
{
    public function __invoke(ContainerInterface $container): OidcConfiguration
    {
        /** @var OidcDiscovery $discovery */
        $discovery = $container->get(OidcDiscovery::class);
        /** @var SecretCipher $cipher */
        $cipher = $container->get(SecretCipher::class);

        return new OidcConfiguration($discovery, $cipher);
    }
}
