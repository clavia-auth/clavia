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
use Clavia\Adapter\Primary\Http\Scim\ScimUserHandler;
use Clavia\Application\Provisioning\Users\DeleteScimUser;
use Clavia\Application\Provisioning\Users\PatchScimUser;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Application\Provisioning\Users\ReplaceScimUser;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ScimUserHandlerFactory
{
    public function __invoke(ContainerInterface $container): ScimUserHandler
    {
        /** @var ReadScimUsers $read */
        $read = $container->get(ReadScimUsers::class);
        /** @var ReplaceScimUser $replace */
        $replace = $container->get(ReplaceScimUser::class);
        /** @var PatchScimUser $patch */
        $patch = $container->get(PatchScimUser::class);
        /** @var DeleteScimUser $delete */
        $delete = $container->get(DeleteScimUser::class);
        /** @var ScimResponder $responder */
        $responder = $container->get(ScimResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ScimUserHandler($read, $replace, $patch, $delete, $responder, $settings->scimBaseUrl());
    }
}
