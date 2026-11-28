<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\AuthorizationModelsHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\ResourceServers\ReadModelVersions;
use Psr\Container\ContainerInterface;

final class AuthorizationModelsHandlerFactory
{
    public function __invoke(ContainerInterface $container): AuthorizationModelsHandler
    {
        /** @var ReadModelVersions $readModelVersions */
        $readModelVersions = $container->get(ReadModelVersions::class);
        /** @var ManagementResponder $managementResponder */
        $managementResponder = $container->get(ManagementResponder::class);

        return new AuthorizationModelsHandler($readModelVersions, $managementResponder);
    }
}
