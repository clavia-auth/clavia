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
use Clavia\Application\OAuth2\TokenManagement\IntrospectToken;
use Clavia\Application\OAuth2\TokenManagement\IssuedTokens;
use Clavia\Application\OAuth2\Token\ApiClaims;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class IntrospectTokenFactory
{
    public function __invoke(ContainerInterface $container): IntrospectToken
    {
        /** @var ClientAuthenticator $authenticator */
        $authenticator = $container->get(ClientAuthenticator::class);
        /** @var IssuedTokens $tokens */
        $tokens = $container->get(IssuedTokens::class);
        /** @var ClientGrantRepository $clientGrants */
        $clientGrants = $container->get(ClientGrantRepository::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        /** @var ApiClaims $claims */
        $claims = $container->get(ApiClaims::class);

        return new IntrospectToken($authenticator, $tokens, $clientGrants, $resourceServers, $users, $clock, $claims);
    }
}
