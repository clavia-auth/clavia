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
use Clavia\Adapter\Primary\Http\Auth\MfaSettingsHandler;
use Clavia\Application\Authentication\Mfa\BeginTotpEnrollment;
use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\DescribeEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\DescribeMfa;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Mfa\FinishEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Psr\Container\ContainerInterface;

final class MfaSettingsHandlerFactory
{
    public function __invoke(ContainerInterface $container): MfaSettingsHandler
    {
        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var RequireSignIn $requireSignIn */
        $requireSignIn = $container->get(RequireSignIn::class);
        /** @var DescribeMfa $describeMfa */
        $describeMfa = $container->get(DescribeMfa::class);
        /** @var BeginTotpEnrollment $begin */
        $begin = $container->get(BeginTotpEnrollment::class);
        /** @var ResumeTotpEnrollment $resume */
        $resume = $container->get(ResumeTotpEnrollment::class);
        /** @var ConfirmTotpEnrollment $confirm */
        $confirm = $container->get(ConfirmTotpEnrollment::class);
        /** @var DisableMfa $disable */
        $disable = $container->get(DisableMfa::class);
        /** @var DescribeEnrolmentOnTheWay $onTheWay */
        $onTheWay = $container->get(DescribeEnrolmentOnTheWay::class);
        /** @var FinishEnrolmentOnTheWay $finishOnTheWay */
        $finishOnTheWay = $container->get(FinishEnrolmentOnTheWay::class);
        /** @var AuthPageResponder $responder */
        $responder = $container->get(AuthPageResponder::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new MfaSettingsHandler(
            $resolveEndUser,
            $requireSignIn,
            $describeMfa,
            $begin,
            $resume,
            $confirm,
            $disable,
            $onTheWay,
            $finishOnTheWay,
            $responder,
            $cookies,
        );
    }
}
