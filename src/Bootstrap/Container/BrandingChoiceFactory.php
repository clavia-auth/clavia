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
use Clavia\Adapter\Primary\Http\Shared\BrandingChoice;
use Clavia\Application\Authentication\Branding\DescribeBranding;
use Clavia\Application\Authentication\HeldRequests;
use Clavia\Application\Authentication\ResolveEndUser;
use Psr\Container\ContainerInterface;

final class BrandingChoiceFactory
{
    public function __invoke(ContainerInterface $container): BrandingChoice
    {
        /** @var HeldRequests $held */
        $held = $container->get(HeldRequests::class);
        /** @var DescribeBranding $describe */
        $describe = $container->get(DescribeBranding::class);

        /** @var ResolveEndUser $resolveEndUser */
        $resolveEndUser = $container->get(ResolveEndUser::class);
        /** @var AuthCookies $cookies */
        $cookies = $container->get(AuthCookies::class);

        return new BrandingChoice($held, $describe, $resolveEndUser, $cookies);
    }
}
