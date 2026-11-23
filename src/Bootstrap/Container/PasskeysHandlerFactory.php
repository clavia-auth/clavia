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
use Clavia\Adapter\Primary\Http\Auth\PasskeysHandler;
use Clavia\Application\Authentication\Mfa\DescribeEnrolmentOnTheWay;
use Clavia\Application\Authentication\Passkey\BeginPasskeyRegistration;
use Clavia\Application\Authentication\Passkey\CompletePasskeyRegistration;
use Clavia\Application\Authentication\Passkey\DescribePasskeys;
use Clavia\Application\Authentication\Passkey\RemovePasskey;
use Clavia\Application\Authentication\Passkey\RenamePasskey;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Psr\Container\ContainerInterface;

final class PasskeysHandlerFactory
{
    public function __invoke(ContainerInterface $container): PasskeysHandler
    {
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var RequireSignIn $requireSignIn */
        $requireSignIn = $container->get(RequireSignIn::class);
        /** @var DescribePasskeys $describe */
        $describe = $container->get(DescribePasskeys::class);
        /** @var BeginPasskeyRegistration $begin */
        $begin = $container->get(BeginPasskeyRegistration::class);
        /** @var CompletePasskeyRegistration $complete */
        $complete = $container->get(CompletePasskeyRegistration::class);
        /** @var RenamePasskey $rename */
        $rename = $container->get(RenamePasskey::class);
        /** @var RemovePasskey $remove */
        $remove = $container->get(RemovePasskey::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        /** @var DescribeEnrolmentOnTheWay $onTheWay */
        $onTheWay = $container->get(DescribeEnrolmentOnTheWay::class);

        return new PasskeysHandler(
            $resolveEndUser,
            $requireSignIn,
            $describe,
            $begin,
            $complete,
            $rename,
            $remove,
            $onTheWay,
            $responder,
            $cookies,
        );
    }
}
