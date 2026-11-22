<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passkey\RecentSignIn;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class RecentSignInFactory
{
    public function __invoke(ContainerInterface $container): RecentSignIn
    {
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $window = $settings->passkeyReauthWindow;
        assert($window > 0);

        return new RecentSignIn($clock, $window);
    }
}
