<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\PasswordForgotHandler;
use Clavia\Application\Authentication\Account\RequestPasswordReset;
use Psr\Container\ContainerInterface;

final class PasswordForgotHandlerFactory
{
    public function __invoke(ContainerInterface $container): PasswordForgotHandler
    {
        /** @var RequestPasswordReset $request */
        $request = $container->get(RequestPasswordReset::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);

        return new PasswordForgotHandler($request, $responder);
    }
}
