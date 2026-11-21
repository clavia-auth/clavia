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
use Clavia\Adapter\Primary\Http\Auth\PasswordlessLinkHandler;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\FollowPasswordlessLink;
use Psr\Container\ContainerInterface;

final class PasswordlessLinkHandlerFactory
{
    public function __invoke(ContainerInterface $container): PasswordlessLinkHandler
    {
        /** @var DescribePasswordlessChallenge $describe */
        $describe = $container->get(DescribePasswordlessChallenge::class);
        /** @var FollowPasswordlessLink $follow */
        $follow = $container->get(FollowPasswordlessLink::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new PasswordlessLinkHandler($describe, $follow, $responder, $cookies);
    }
}
