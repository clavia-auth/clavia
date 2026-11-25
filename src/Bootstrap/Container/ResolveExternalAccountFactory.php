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
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Provisioning\ProvisionedAccountRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Psr\Container\ContainerInterface;

final class ResolveExternalAccountFactory
{
    public function __invoke(ContainerInterface $container): ResolveExternalAccount
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ExternalIdentityRepository $identities */
        $identities = $container->get(ExternalIdentityRepository::class);
        /** @var ProvisionedAccountRepository $provisioned */
        $provisioned = $container->get(ProvisionedAccountRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var RandomSource $random */
        $random = $container->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new ResolveExternalAccount(
            $users,
            $identities,
            $provisioned,
            $transactions,
            $random,
            $clock,
            $settings->socialAutoLink,
        );
    }
}
