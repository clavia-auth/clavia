<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\Provisioning\AuthenticateProvisioningToken;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class AuthenticateProvisioningTokenFactory
{
    public function __invoke(ContainerInterface $container): AuthenticateProvisioningToken
    {
        /** @var ProvisioningTokenRepository $tokens */
        $tokens = $container->get(ProvisioningTokenRepository::class);
        /** @var ConnectionRepository $connections */
        $connections = $container->get(ConnectionRepository::class);
        /** @var ClientFailureThrottle $throttle */
        $throttle = $container->get(ClientFailureThrottle::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new AuthenticateProvisioningToken($tokens, $connections, $throttle, $clock);
    }
}
