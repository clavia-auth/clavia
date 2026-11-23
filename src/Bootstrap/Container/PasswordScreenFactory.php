<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Account\PasswordScreen;
use Clavia\Application\Port\BreachedPasswords;
use Psr\Container\ContainerInterface;

final class PasswordScreenFactory
{
    public function __invoke(ContainerInterface $container): PasswordScreen
    {
        /** @var BreachedPasswords $breaches */
        $breaches = $container->get(BreachedPasswords::class);

        return new PasswordScreen($breaches);
    }
}
