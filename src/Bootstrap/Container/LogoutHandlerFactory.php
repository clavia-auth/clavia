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
use Clavia\Adapter\Primary\Http\Auth\LogoutHandler;
use Clavia\Application\Authentication\SignOut;
use Psr\Container\ContainerInterface;

final class LogoutHandlerFactory
{
    public function __invoke(ContainerInterface $container): LogoutHandler
    {
        /** @var SignOut $signOut */
        $signOut = $container->get(SignOut::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new LogoutHandler($signOut, $responder, $cookies);
    }
}
