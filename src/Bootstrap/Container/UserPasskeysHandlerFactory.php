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
use Clavia\Adapter\Primary\Http\Management\UserPasskeysHandler;
use Clavia\Application\Management\Users\ReadUserPasskeys;
use Clavia\Application\Management\Users\RemoveUserPasskey;
use Psr\Container\ContainerInterface;

final class UserPasskeysHandlerFactory
{
    public function __invoke(ContainerInterface $container): UserPasskeysHandler
    {
        /** @var ReadUserPasskeys $read */
        $read = $container->get(ReadUserPasskeys::class);
        /** @var RemoveUserPasskey $remove */
        $remove = $container->get(RemoveUserPasskey::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new UserPasskeysHandler($read, $remove, $responder);
    }
}
