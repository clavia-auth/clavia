<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Caller\AuthenticateManagementCaller;
use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class AuthenticateManagementCallerFactory
{
    public function __invoke(ContainerInterface $container): AuthenticateManagementCaller
    {
        /** @var AccessTokenRepository $tokens */
        $tokens = $container->get(AccessTokenRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var CheckSenderConstraint $senderConstraint */
        $senderConstraint = $container->get(CheckSenderConstraint::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new AuthenticateManagementCaller(
            $tokens,
            $users,
            $clock,
            Audience::fromString($settings->managementApiAudience()),
            $resourceServers,
            $senderConstraint,
        );
    }
}
