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
use Clavia\Adapter\Primary\Http\Management\RotateClientSecretHandler;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\RotateClientSecret;
use Psr\Container\ContainerInterface;

final class RotateClientSecretHandlerFactory
{
    public function __invoke(ContainerInterface $container): RotateClientSecretHandler
    {
        /** @var RotateClientSecret $rotate */
        $rotate = $container->get(RotateClientSecret::class);
        /** @var ReadClients $read */
        $read = $container->get(ReadClients::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new RotateClientSecretHandler($rotate, $read, $responder);
    }
}
