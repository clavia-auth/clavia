<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignOut;
use Clavia\Application\Oidc\Logout\BackChannelLogout;
use Clavia\Domain\Client\ClientRepository;
use Psr\Container\ContainerInterface;

final class SignOutFactory
{
    public function __invoke(ContainerInterface $container): SignOut
    {
        /** @var Sessions $sessions */
        $sessions = $container->get(Sessions::class);
        /** @var BackChannelLogout $backChannel */
        $backChannel = $container->get(BackChannelLogout::class);
        /** @var ClientRepository $clients */
        $clients = $container->get(ClientRepository::class);

        return new SignOut($sessions, $backChannel, $clients);
    }
}
