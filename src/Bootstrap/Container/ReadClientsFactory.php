<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Psr\Container\ContainerInterface;

final class ReadClientsFactory
{
    public function __invoke(ContainerInterface $container): ReadClients
    {
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ClientRegistrationRepository $registrations */
        $registrations = $container->get(ClientRegistrationRepository::class);

        return new ReadClients($clients, $registrations);
    }
}
