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
use Clavia\Adapter\Primary\Http\Management\SamlKeysHandler;
use Clavia\Application\Connection\Saml\ListServiceProviderKeys;
use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Psr\Container\ContainerInterface;

final class SamlKeysHandlerFactory
{
    public function __invoke(ContainerInterface $container): SamlKeysHandler
    {
        /** @var ListServiceProviderKeys $list */
        $list = $container->get(ListServiceProviderKeys::class);
        /** @var RotateServiceProviderKeys $rotate */
        $rotate = $container->get(RotateServiceProviderKeys::class);
        /** @var ManagementResponder $responder */
        $responder = $container->get(ManagementResponder::class);

        return new SamlKeysHandler($list, $rotate, $responder);
    }
}
