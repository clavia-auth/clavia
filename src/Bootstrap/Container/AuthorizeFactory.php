<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class AuthorizeFactory
{
    public function __invoke(ContainerInterface $container): Authorize
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var AuthorizationCodeRepository $codes */
        $codes = $container->get(AuthorizationCodeRepository::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var NonceRegistry $nonces */
        $nonces = $container->get(NonceRegistry::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var ConsentRepository $consents */
        $consents = $container->get(ConsentRepository::class);
        /** @var ConsentStateStore $consentStates */
        $consentStates = $container->get(ConsentStateStore::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        $lifetime = $settings->authorizationCodeLifetime;
        assert($lifetime > 0);
        // A used nonce is remembered until neither the code carrying it nor an ID token
        // minted from that code can still be valid.
        $nonceLifetime = $lifetime + $settings->idTokenLifetime;
        assert($nonceLifetime > 0);

        return new Authorize(
            $clients,
            $codes,
            $loginStates,
            $nonces,
            $resourceServers,
            $roles,
            $consents,
            $consentStates,
            $secrets,
            $random,
            $clock,
            ScopeSet::fromString(implode(' ', $settings->scopesSupported)),
            $lifetime,
            $nonceLifetime,
        );
    }
}
