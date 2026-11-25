<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Scim\ScimResponder;
use Clavia\Adapter\Primary\Http\Scim\ScimUsersHandler;
use Clavia\Application\Provisioning\Users\CreateScimUser;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ScimUsersHandlerFactory
{
    public function __invoke(ContainerInterface $container): ScimUsersHandler
    {
        /** @var CreateScimUser $create */
        $create = $container->get(CreateScimUser::class);
        /** @var ReadScimUsers $read */
        $read = $container->get(ReadScimUsers::class);
        /** @var ScimResponder $responder */
        $responder = $container->get(ScimResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ScimUsersHandler($create, $read, $responder, $settings->scimBaseUrl());
    }
}
