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
use Clavia\Adapter\Primary\Http\OAuth2\AuthorizeHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Psr\Container\ContainerInterface;

final class AuthorizeHandlerFactory
{
    public function __invoke(ContainerInterface $container): AuthorizeHandler
    {
        /** @var Authorize $authorize */
        $authorize = $container->get(Authorize::class);
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var OAuth2Responder $responder */
        $responder = $container->get(OAuth2Responder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new AuthorizeHandler($authorize, $resolveEndUser, $responder, $cookies);
    }
}
