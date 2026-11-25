<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\External\Saml\BeginSamlSignIn;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class BeginSamlSignInFactory
{
    public function __invoke(ContainerInterface $container): BeginSamlSignIn
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ExternalSignInStore $pending */
        $pending = $container->get(ExternalSignInStore::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var SamlServiceProvider $saml */
        $saml = $container->get(SamlServiceProvider::class);
        /** @var SamlServiceProviderEndpoints $endpoints */
        $endpoints = $container->get(SamlServiceProviderEndpoints::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new BeginSamlSignIn(
            $access,
            $clients,
            $pending,
            $loginStates,
            $saml,
            $endpoints,
            $secrets,
            $random,
            $clock,
        );
    }
}
