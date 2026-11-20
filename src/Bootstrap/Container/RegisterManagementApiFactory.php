<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Port\TransactionManager;
use Clavia\Configuration\Settings;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RegisterManagementApiFactory
{
    public function __invoke(ContainerInterface $container): RegisterManagementApi
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var TransactionManager $transactions */
        $transactions = $container->get(TransactionManager::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new RegisterManagementApi(
            $resourceServers,
            $transactions,
            $secrets,
            $clock,
            Audience::fromString($settings->managementApiAudience()),
        );
    }
}
