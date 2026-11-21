<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\TokenManagement\IssuedTokens;
use Clavia\Application\OAuth2\TokenManagement\RevokeToken;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class RevokeTokenFactory
{
    public function __invoke(ContainerInterface $container): RevokeToken
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var IssuedTokens $tokens */
        $tokens = $container->get(IssuedTokens::class);
        /** @var AccessTokenRepository $accessTokens */
        $accessTokens = $container->get(AccessTokenRepository::class);
        /** @var RefreshTokenRepository $refreshTokens */
        $refreshTokens = $container->get(RefreshTokenRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new RevokeToken($authenticator, $tokens, $accessTokens, $refreshTokens, $transactions, $clock, $events);
    }
}
