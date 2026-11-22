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
use Clavia\Adapter\Primary\Http\Auth\LoginForm;
use Clavia\Adapter\Primary\Http\Auth\LoginHandler;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Psr\Container\ContainerInterface;

final class LoginHandlerFactory
{
    public function __invoke(ContainerInterface $container): LoginHandler
    {
        /** @var SignInWithPassword $signIn */
        $signIn = $container->get(SignInWithPassword::class);
        /** @var LoginForm $loginForm */
        $loginForm = $container->get(LoginForm::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new LoginHandler($signIn, $loginForm, $responder, $cookies);
    }
}
