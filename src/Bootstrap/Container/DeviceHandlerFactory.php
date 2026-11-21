<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\DeviceHandler;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Device\DecideDeviceRequest;
use Clavia\Application\OAuth2\Device\DescribeDeviceRequest;
use Clavia\Application\OAuth2\Device\UserCodeThrottle;
use Psr\Container\ContainerInterface;

final class DeviceHandlerFactory
{
    public function __invoke(ContainerInterface $container): DeviceHandler
    {
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var RequireSignIn $requireSignIn */
        $requireSignIn = $container->get(RequireSignIn::class);
        /** @var DescribeDeviceRequest $describe */
        $describe = $container->get(DescribeDeviceRequest::class);
        /** @var DecideDeviceRequest $decide */
        $decide = $container->get(DecideDeviceRequest::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        /** @var UserCodeThrottle $throttle */
        $throttle = $container->get(UserCodeThrottle::class);

        return new DeviceHandler($resolveEndUser, $requireSignIn, $describe, $decide, $responder, $cookies, $throttle);
    }
}
