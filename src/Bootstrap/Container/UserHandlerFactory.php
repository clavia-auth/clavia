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
use Clavia\Adapter\Primary\Http\Management\UserHandler;
use Clavia\Application\Management\Users\DeleteUser;
use Clavia\Application\Management\Users\ReadUsers;
use Clavia\Application\Management\Users\UpdateUser;
use Psr\Container\ContainerInterface;

final class UserHandlerFactory
{
    public function __invoke(ContainerInterface $container): UserHandler
    {
        /** @var ReadUsers $read */
        $read = $container->get(ReadUsers::class);
        /** @var UpdateUser $update */
        $update = $container->get(UpdateUser::class);
        /** @var DeleteUser $delete */
        $delete = $container->get(DeleteUser::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new UserHandler($read, $update, $delete, $responder);
    }
}
