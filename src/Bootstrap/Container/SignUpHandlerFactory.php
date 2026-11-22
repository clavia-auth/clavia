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
use Clavia\Adapter\Primary\Http\Auth\SignUpHandler;
use Clavia\Application\Authentication\Account\DescribeSignUpPage;
use Clavia\Application\Authentication\Account\SignUp;
use Psr\Container\ContainerInterface;

final class SignUpHandlerFactory
{
    public function __invoke(ContainerInterface $container): SignUpHandler
    {
        /** @var DescribeSignUpPage $describe */
        $describe = $container->get(DescribeSignUpPage::class);
        /** @var SignUp $signUp */
        $signUp = $container->get(SignUp::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new SignUpHandler($describe, $signUp, $responder, $cookies);
    }
}
