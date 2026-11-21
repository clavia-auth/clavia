<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\TokenManagement\IssuedTokens;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Psr\Container\ContainerInterface;

final class IssuedTokensFactory
{
    public function __invoke(ContainerInterface $container): IssuedTokens
    {
        /** @var AccessTokenRepository $accessTokens */
        $accessTokens = $container->get(AccessTokenRepository::class);
        /** @var RefreshTokenRepository $refreshTokens */
        $refreshTokens = $container->get(RefreshTokenRepository::class);

        return new IssuedTokens($accessTokens, $refreshTokens);
    }
}
