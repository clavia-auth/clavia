<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Connections\SamlConfiguration;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Psr\Container\ContainerInterface;

final class SamlConfigurationFactory
{
    public function __invoke(ContainerInterface $container): SamlConfiguration
    {
        /** @var SamlServiceProvider $saml */
        $saml = $container->get(SamlServiceProvider::class);
        /** @var SamlMetadataSource $source */
        $source = $container->get(SamlMetadataSource::class);

        return new SamlConfiguration($saml, $source);
    }
}
