<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Adapter\Primary\Http\Management\UsersHandler;
use Clavia\Application\Management\Users\CreateUser;
use Clavia\Application\Management\Users\ReadUsers;
use Psr\Container\ContainerInterface;

final class UsersHandlerFactory
{
    public function __invoke(ContainerInterface $container): UsersHandler
    {
        /** @var ReadUsers $read */
        $read = $container->get(ReadUsers::class);
        /** @var CreateUser $create */
        $create = $container->get(CreateUser::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new UsersHandler($read, $create, $responder);
    }
}
