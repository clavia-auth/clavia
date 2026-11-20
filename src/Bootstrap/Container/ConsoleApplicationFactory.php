<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Bootstrap\ConfigProvider;
use Clavia\Configuration\Version;
use Psr\Container\ContainerInterface;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\CommandLoader\ContainerCommandLoader;

final class ConsoleApplicationFactory
{
    public function __invoke(ContainerInterface $container): Application
    {
        $application = new Application('Clavia', Version::CURRENT);
        $application->setCommandLoader(new ContainerCommandLoader($container, ConfigProvider::CONSOLE_COMMANDS));

        return $application;
    }
}
