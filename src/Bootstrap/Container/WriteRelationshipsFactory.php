<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authorization\Relationships\WriteRelationships;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class WriteRelationshipsFactory
{
    public function __invoke(ContainerInterface $container): WriteRelationships
    {
        /** @var SpokenForApi $apis */
        $apis = $container->get(SpokenForApi::class);
        /** @var DecisionEngine $engine */
        $engine = $container->get(DecisionEngine::class);
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);

        return new WriteRelationships(
            $apis,
            $engine,
            $users,
            $clients,
        );
    }
}
