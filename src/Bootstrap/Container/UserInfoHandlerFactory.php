<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Oidc\UserInfoHandler;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Psr\Container\ContainerInterface;

final class UserInfoHandlerFactory
{
    public function __invoke(ContainerInterface $container): UserInfoHandler
    {
        /** @var ReadUserInfo $readUserInfo */
        $readUserInfo = $container->get(ReadUserInfo::class);
        /** @var BearerChallenger $challenger */
        $challenger = $container->get(BearerChallenger::class);

        return new UserInfoHandler($readUserInfo, $challenger);
    }
}
