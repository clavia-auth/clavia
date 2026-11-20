<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use Clavia\Ui\Cli\ShowConfigCommand;
use Psr\Container\ContainerInterface;

final class ShowConfigCommandFactory
{
    public function __invoke(ContainerInterface $container): ShowConfigCommand
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ShowConfigCommand($settings);
    }
}
