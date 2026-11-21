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
use Clavia\Adapter\Primary\Http\Auth\ConsentHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Consent\DecideConsent;
use Clavia\Application\OAuth2\Consent\DescribeConsent;
use Psr\Container\ContainerInterface;

final class ConsentHandlerFactory
{
    public function __invoke(ContainerInterface $container): ConsentHandler
    {
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var RequireSignIn $requireSignIn */
        $requireSignIn = $container->get(RequireSignIn::class);
        /** @var DescribeConsent $describe */
        $describe = $container->get(DescribeConsent::class);
        /** @var DecideConsent $decide */
        $decide = $container->get(DecideConsent::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var OAuth2Responder $oauth2 */
        $oauth2 = $container->get(OAuth2Responder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new ConsentHandler($resolveEndUser, $requireSignIn, $describe, $decide, $responder, $oauth2, $cookies);
    }
}
