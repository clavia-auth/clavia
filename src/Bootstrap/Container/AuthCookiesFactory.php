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
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class AuthCookiesFactory
{
    public function __invoke(ContainerInterface $container): AuthCookies
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $name = $settings->sessionCookieName;
        $lifetime = $settings->sessionAbsoluteLifetime;
        $challengeLifetime = $settings->mfaChallengeLifetime;
        $codeLifetime = $settings->passwordlessCodeLifetime;
        assert($name !== '' && $lifetime > 0 && $challengeLifetime > 0 && $codeLifetime > 0);

        return new AuthCookies(
            $name,
            $lifetime,
            $settings->sessionCookieSecure,
            $challengeLifetime,
            $codeLifetime,
        );
    }
}
