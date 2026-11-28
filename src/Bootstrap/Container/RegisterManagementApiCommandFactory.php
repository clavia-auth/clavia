<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\RegisterManagementApiCommand;
use Clavia\Application\Management\Provisioning\RegisterAuthorizationApi;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class RegisterManagementApiCommandFactory
{
    public function __invoke(ContainerInterface $container): RegisterManagementApiCommand
    {
        /** @var RegisterManagementApi $register */
        $register = $container->get(RegisterManagementApi::class);

        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var RegisterAuthorizationApi|null $registerAuthorizationApi */
        $registerAuthorizationApi = $settings->fineGrainedAuthorization()
            ? $container->get(RegisterAuthorizationApi::class)
            : null;

        return new RegisterManagementApiCommand($register, $registerAuthorizationApi);
    }
}
