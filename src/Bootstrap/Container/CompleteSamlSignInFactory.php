<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Application\Authentication\External\Saml\CompleteSamlSignIn;
use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Connection\Saml\SamlServiceProviderEndpoints;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Psr\Container\ContainerInterface;

final class CompleteSamlSignInFactory
{
    public function __invoke(ContainerInterface $container): CompleteSamlSignIn
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var SamlResponseStore $responses */
        $responses = $container->get(SamlResponseStore::class);
        /** @var ExternalSignInStore $pending */
        $pending = $container->get(ExternalSignInStore::class);
        /** @var SamlServiceProvider $saml */
        $saml = $container->get(SamlServiceProvider::class);
        /** @var SamlServiceProviderEndpoints $endpoints */
        $endpoints = $container->get(SamlServiceProviderEndpoints::class);
        /** @var SamlAssertionReplayCache $assertions */
        $assertions = $container->get(SamlAssertionReplayCache::class);
        /** @var ResolveExternalAccount $resolveAccount */
        $resolveAccount = $container->get(ResolveExternalAccount::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);
        /** @var ServiceProviderKeys $keys */
        $keys = $container->get(ServiceProviderKeys::class);
        /** @var LoginThrottle $throttle */
        $throttle = $container->get(LoginThrottle::class);

        return new CompleteSamlSignIn(
            $access,
            $clients,
            $responses,
            $pending,
            $saml,
            $endpoints,
            $assertions,
            $keys,
            $throttle,
            $resolveAccount,
            $loginStates,
            $completeFirstFactor,
            $clock,
            $events,
        );
    }
}
