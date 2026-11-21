<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\OAuth2\IntrospectionHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Application\OAuth2\TokenManagement\IntrospectToken;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class IntrospectionHandlerFactory
{
    public function __invoke(ContainerInterface $container): IntrospectionHandler
    {
        /** @var IntrospectToken $introspect */
        $introspect = $container->get(IntrospectToken::class);
        /** @var OAuth2Responder $responder */
        $responder = $container->get(OAuth2Responder::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new IntrospectionHandler($introspect, $responder, $settings->issuer());
    }
}
