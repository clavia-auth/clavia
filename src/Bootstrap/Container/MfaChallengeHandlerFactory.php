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
use Clavia\Adapter\Primary\Http\Auth\MfaChallengeHandler;
use Clavia\Application\Authentication\Mfa\BeginPasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\CompletePasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Psr\Container\ContainerInterface;

final class MfaChallengeHandlerFactory
{
    public function __invoke(ContainerInterface $container): MfaChallengeHandler
    {
        /** @var DescribeSecondFactorPage $describe */
        $describe = $container->get(DescribeSecondFactorPage::class);
        /** @var CompleteSecondFactor $complete */
        $complete = $container->get(CompleteSecondFactor::class);
        /** @var BeginPasskeySecondFactor $beginPasskey */
        $beginPasskey = $container->get(BeginPasskeySecondFactor::class);
        /** @var CompletePasskeySecondFactor $completePasskey */
        $completePasskey = $container->get(CompletePasskeySecondFactor::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new MfaChallengeHandler($describe, $complete, $beginPasskey, $completePasskey, $responder, $cookies);
    }
}
