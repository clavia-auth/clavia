<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\AuthorizationCodeGrant;
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class AuthorizationCodeGrantFactory
{
    public function __invoke(ContainerInterface $container): AuthorizationCodeGrant
    {
        /** @var AuthorizationCodeRepository $codes */
        $codes = $container->get(AuthorizationCodeRepository::class);
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
        /** @var IdTokenIssuer $idTokens */
        $idTokens = $container->get(IdTokenIssuer::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $lifetime = $settings->accessTokenLifetime;
        assert($lifetime > 0);

        return new AuthorizationCodeGrant(
            $codes,
            $tokens,
            $users,
            $transactions,
            $secrets,
            $random,
            $clock,
            $idTokens,
            $resourceServers,
            $roles,
            ScopeSet::fromString(implode(' ', $settings->scopesSupported)),
            $lifetime,
        );
    }
}
