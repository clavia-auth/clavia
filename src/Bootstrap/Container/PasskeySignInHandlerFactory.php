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
use Clavia\Adapter\Primary\Http\Auth\PasskeySignInHandler;
use Clavia\Application\Authentication\SignIn\SignInWithPasskey;
use Psr\Container\ContainerInterface;

final class PasskeySignInHandlerFactory
{
    public function __invoke(ContainerInterface $container): PasskeySignInHandler
    {
        /** @var SignInWithPasskey $signIn */
        $signIn = $container->get(SignInWithPasskey::class);
        /** @var LoginForm $loginForm */
        $loginForm = $container->get(LoginForm::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new PasskeySignInHandler($signIn, $loginForm, $responder, $cookies);
    }
}
