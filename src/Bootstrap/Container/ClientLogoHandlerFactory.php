<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Management\ClientLogoHandler;
use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Management\Clients\ReadClientLogo;
use Clavia\Application\Management\Clients\RemoveClientLogo;
use Clavia\Application\Management\Clients\SetClientLogo;
use Psr\Container\ContainerInterface;

final class ClientLogoHandlerFactory
{
    public function __invoke(ContainerInterface $container): ClientLogoHandler
    {
        /** @var ReadClientLogo $read */
        $read = $container->get(ReadClientLogo::class);
        /** @var SetClientLogo $set */
        $set = $container->get(SetClientLogo::class);
        /** @var RemoveClientLogo $remove */
        $remove = $container->get(RemoveClientLogo::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new ClientLogoHandler($read, $set, $remove, $responder);
    }
}
