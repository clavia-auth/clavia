<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\RefreshTokenGrant;
use Clavia\Application\OAuth2\Token\UserScope;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RefreshTokenGrantFactory
{
    public function __invoke(ContainerInterface $container): RefreshTokenGrant
    {
        /** @var RefreshTokenRepository $refreshTokens */
        $refreshTokens = $container->get(RefreshTokenRepository::class);
        /** @var AccessTokenRepository $tokens */
        $tokens = $container->get(AccessTokenRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var UserScope $userScope */
        $userScope = $container->get(UserScope::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $lifetime = $settings->accessTokenLifetime;
        assert($lifetime > 0);
        $refreshLifetime = $settings->refreshTokenLifetime;
        assert($refreshLifetime > 0);

        return new RefreshTokenGrant(
            $refreshTokens,
            $tokens,
            $users,
            $transactions,
            $secrets,
            $random,
            $clock,
            $userScope,
            $lifetime,
            $refreshLifetime,
        );
    }
}
