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
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use Psr\Container\ContainerInterface;

final class RegisterMachineClientFactory
{
    public function __invoke(ContainerInterface $container): RegisterMachineClient
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var PasswordHasher $hasher */
        $hasher = $container->get(PasswordHasher::class);
        /** @var SecretGenerator $secrets */
        $secrets = $container->get(SecretGenerator::class);
        /** @var Clock $clock */
        $clock = $container->get(Clock::class);

        return new RegisterMachineClient($clients, $hasher, $secrets, $clock);
    }
}
