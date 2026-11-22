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
use Clavia\Adapter\Primary\Http\Auth\PasswordResetHandler;
use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Clavia\Application\Authentication\Account\ResetPassword;
use Psr\Container\ContainerInterface;

final class PasswordResetHandlerFactory
{
    public function __invoke(ContainerInterface $container): PasswordResetHandler
    {
        /** @var DescribeAccountLink $describe */
        $describe = $container->get(DescribeAccountLink::class);
        /** @var ResetPassword $reset */
        $reset = $container->get(ResetPassword::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new PasswordResetHandler($describe, $reset, $responder, $cookies);
    }
}
