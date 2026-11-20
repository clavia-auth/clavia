<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\SeedDevelopmentDataCommand;
use Clavia\Application\Development\SeedDashboardClient;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class SeedDevelopmentDataCommandFactory
{
    /** The dashboard's build configuration, beside the checkout's `frontend/`. */
    public const string DASHBOARD_ENV_FILE = __DIR__ . '/../../../frontend/.env.local';

    public function __invoke(ContainerInterface $container): SeedDevelopmentDataCommand
    {
        /** @var SeedDevelopmentData $seed */
        $seed = $container->get(SeedDevelopmentData::class);
        /** @var SeedManagementAccess $seedManagementAccess */
        $seedManagementAccess = $container->get(SeedManagementAccess::class);
        /** @var SeedDashboardClient $seedDashboard */
        $seedDashboard = $container->get(SeedDashboardClient::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new SeedDevelopmentDataCommand(
            $seed,
            $seedManagementAccess,
            $seedDashboard,
            $settings->rootDomain,
            $settings->issuer(),
            $settings->managementHost(),
            self::DASHBOARD_ENV_FILE,
        );
    }
}
