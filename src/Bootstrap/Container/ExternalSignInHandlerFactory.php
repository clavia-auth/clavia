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
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInHandler;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Application\Authentication\External\BeginExternalSignIn;
use Psr\Container\ContainerInterface;

final class ExternalSignInHandlerFactory
{
    public function __invoke(ContainerInterface $container): ExternalSignInHandler
    {
        /** @var BeginExternalSignIn $begin */
        $begin = $container->get(BeginExternalSignIn::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var ErrorResponder $errors */
        $errors = $container->get(ErrorResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new ExternalSignInHandler($begin, $responder, $errors, $cookies);
    }
}
