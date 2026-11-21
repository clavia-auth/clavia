<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Consent\HeldConsents;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Psr\Container\ContainerInterface;

final class HeldConsentsFactory
{
    public function __invoke(ContainerInterface $container): HeldConsents
    {
        /** @var ConsentStateStore $states */
        $states = $container->get(ConsentStateStore::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);

        return new HeldConsents($states, $users, $clients, $resourceServers);
    }
}
