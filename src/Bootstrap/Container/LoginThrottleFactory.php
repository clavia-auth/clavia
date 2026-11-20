<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class LoginThrottleFactory
{
    public function __invoke(ContainerInterface $container): LoginThrottle
    {
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $maxAttempts = $settings->loginMaxAttempts;
        $window = $settings->loginAttemptWindow;
        assert($maxAttempts > 0 && $window > 0);

        return new LoginThrottle($counter, $maxAttempts, $window);
    }
}
