<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Scim\ScimGroupHandler;
use Clavia\Adapter\Primary\Http\Scim\ScimResponder;
use Clavia\Application\Provisioning\Groups\DeleteScimGroup;
use Clavia\Application\Provisioning\Groups\PatchScimGroup;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Application\Provisioning\Groups\ReplaceScimGroup;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ScimGroupHandlerFactory
{
    public function __invoke(ContainerInterface $container): ScimGroupHandler
    {
        /** @var ReadScimGroups $read */
        $read = $container->get(ReadScimGroups::class);
        /** @var ReplaceScimGroup $replace */
        $replace = $container->get(ReplaceScimGroup::class);
        /** @var PatchScimGroup $patch */
        $patch = $container->get(PatchScimGroup::class);
        /** @var DeleteScimGroup $delete */
        $delete = $container->get(DeleteScimGroup::class);
        /** @var ScimResponder $responder */
        $responder = $container->get(ScimResponder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ScimGroupHandler($read, $replace, $patch, $delete, $responder, $settings->scimBaseUrl());
    }
}
