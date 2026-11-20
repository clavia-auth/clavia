<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\GrantClientAccessCommand;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class GrantClientAccessCommandFactory
{
    public function __invoke(ContainerInterface $container): GrantClientAccessCommand
    {
        /** @var GrantClientAccess $grant */
        $grant = $container->get(GrantClientAccess::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new GrantClientAccessCommand($grant, $settings->managementApiAudience(), $settings->issuer());
    }
}
