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
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Application\Port\IdentityProviders;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class CompleteExternalSignInFactory
{
    public function __invoke(ContainerInterface $container): CompleteExternalSignIn
    {
        /** @var IdentityProviders $providers */
        $providers = $container->get(IdentityProviders::class);
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

        return new CompleteExternalSignIn(
            $providers,
            $pending,
            $resolveAccount,
            $loginStates,
            $completeFirstFactor,
            $settings->issuer(),
        );
    }
}
