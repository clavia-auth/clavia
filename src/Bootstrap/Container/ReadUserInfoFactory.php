<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\ProtectedResource\CheckSenderConstraint;
use Clavia\Application\Oidc\ApplicationClaims;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class ReadUserInfoFactory
{
    public function __invoke(ContainerInterface $container): ReadUserInfo
    {
        /** @var AccessTokenRepository $tokens */
        $tokens = $container->get(AccessTokenRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        /** @var CheckSenderConstraint $senderConstraint */
        $senderConstraint = $container->get(CheckSenderConstraint::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var ApplicationClaims $claims */
        $claims = $container->get(ApplicationClaims::class);

        return new ReadUserInfo(
            $tokens,
            $users,
            $clock,
            $senderConstraint,
            $settings->issuer() . ProviderMetadata::USERINFO_ENDPOINT,
            $claims,
        );
    }
}
