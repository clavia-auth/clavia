<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\External\CompleteExternalSignIn;
use Clavia\Application\Authentication\External\ResolveExternalAccount;
use Clavia\Application\Authentication\SignIn\CompleteFirstFactor;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class CompleteExternalSignInFactory
{
    public function __invoke(ContainerInterface $container): CompleteExternalSignIn
    {
        /** @var ConnectionAccess $access */
        $access = $container->get(ConnectionAccess::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ExternalSignInStore $pending */
        $pending = $container->get(ExternalSignInStore::class);
        /** @var ResolveExternalAccount $resolveAccount */
        $resolveAccount = $container->get(ResolveExternalAccount::class);
        /** @var LoginStateStore $loginStates */
        $loginStates = $container->get(LoginStateStore::class);
        /** @var CompleteFirstFactor $completeFirstFactor */
        $completeFirstFactor = $container->get(CompleteFirstFactor::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        /** @var DomainEvents $events */
        $events = $container->get(DomainEvents::class);

        return new CompleteExternalSignIn(
            $access,
            $clients,
            $pending,
            $resolveAccount,
            $loginStates,
            $completeFirstFactor,
            $settings->issuer(),
            $events,
        );
    }
}
