<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\OAuth2\DeviceAuthorizationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Application\OAuth2\Device\RequestDeviceAuthorization;
use Psr\Container\ContainerInterface;

final class DeviceAuthorizationHandlerFactory
{
    public function __invoke(ContainerInterface $container): DeviceAuthorizationHandler
    {
        /** @var RequestDeviceAuthorization $requestAuthorization */
        $requestAuthorization = $container->get(RequestDeviceAuthorization::class);
        /** @var OAuth2Responder $responder */
        $responder = $container->get(OAuth2Responder::class);

        return new DeviceAuthorizationHandler($requestAuthorization, $responder);
    }
}
