<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class SeedManagementAccessFactory
{
    public function __invoke(ContainerInterface $container): SeedManagementAccess
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var RegisterManagementApi $registerManagementApi */
        $registerManagementApi = $container->get(RegisterManagementApi::class);
        /** @var RegisterMachineClient $registerMachineClient */
        $registerMachineClient = $container->get(RegisterMachineClient::class);
        /** @var GrantClientAccess $grantClientAccess */
        $grantClientAccess = $container->get(GrantClientAccess::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new SeedManagementAccess(
            $clients,
            $registerManagementApi,
            $registerMachineClient,
            $grantClientAccess,
            $transactions,
            $settings->isDevelopment(),
        );
    }
}
