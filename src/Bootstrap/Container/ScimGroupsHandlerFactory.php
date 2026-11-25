<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Scim\ScimGroupsHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimResponder;
use Clavia\Application\Provisioning\Groups\CreateScimGroup;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ScimGroupsHandlerFactory
{
    public function __invoke(ContainerInterface $container): ScimGroupsHandler
    {
        /** @var CreateScimGroup $create */
        $create = $container->get(CreateScimGroup::class);
        /** @var ReadScimGroups $read */
        $read = $container->get(ReadScimGroups::class);
        /** @var ScimResponder $responder */
        $responder = $container->get(ScimResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ScimGroupsHandler($create, $read, $responder, $settings->scimBaseUrl());
    }
}
