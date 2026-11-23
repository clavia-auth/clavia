<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Clients\Registration\ReadClientConfiguration;
use Clavia\Application\Clients\Registration\RegisteredClients;
use Psr\Container\ContainerInterface;

final class ReadClientConfigurationFactory
{
    public function __invoke(ContainerInterface $container): ReadClientConfiguration
    {
        /** @var RegisteredClients $registered */
        $registered = $container->get(RegisteredClients::class);

        return new ReadClientConfiguration($registered);
    }
}
