<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Passwordless\PasswordlessSendLimit;
use Clavia\Application\Port\AttemptCounter;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class PasswordlessSendLimitFactory
{
    public function __invoke(ContainerInterface $container): PasswordlessSendLimit
    {
        /** @var AttemptCounter $counter */
        $counter = $container->get(AttemptCounter::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $limit = $settings->passwordlessSendLimit;
        assert($limit > 0);

        return new PasswordlessSendLimit($counter, $limit);
    }
}
