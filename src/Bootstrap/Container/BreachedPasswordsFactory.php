<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\BreachedPasswords\NoBreachedPasswords;
use Clavia\Adapter\Secondary\BreachedPasswords\PwnedPasswordsRange;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Application\Port\BreachedPasswords;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Pwned Passwords when `CLAVIA_BREACHED_PASSWORD_CHECK` is on; otherwise no check, and
 * nothing leaves the server.
 */
final class BreachedPasswordsFactory
{
    public function __invoke(ContainerInterface $container): BreachedPasswords
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        if (! $settings->breachedPasswordCheck) {
            return new NoBreachedPasswords();
        }

        /** @var ClientInterface $http */
        $http = $container->get(ClientInterface::class);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var OutboundUrlPolicy $policy */
        $policy = $container->get(OutboundUrlPolicy::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new PwnedPasswordsRange($http, $requests, $policy, $logger);
    }
}
