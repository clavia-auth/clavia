<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\ClientConnections;
use Clavia\Application\Management\Clients\RegisterClient;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RegisterClientFactory
{
    public function __invoke(ContainerInterface $container): RegisterClient
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);
        /** @var ClientConnections $connections */
        $connections = $container->get(ClientConnections::class);

        return new RegisterClient($clients, $hasher, $secrets, $clock, $connections);
    }
}
