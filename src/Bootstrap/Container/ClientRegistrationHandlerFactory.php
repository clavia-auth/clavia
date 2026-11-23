<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\OAuth2\ClientRegistrationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Clients\Registration\RegisterClientDynamically;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;

final class ClientRegistrationHandlerFactory
{
    public function __invoke(ContainerInterface $container): ClientRegistrationHandler
    {
        /** @var RegisterClientDynamically $register */
        $register = $container->get(RegisterClientDynamically::class);
        /** @var OAuth2Responder $responder */
        $responder = $container->get(OAuth2Responder::class);
        /** @var BearerChallenger $challenger */
        $challenger = $container->get(BearerChallenger::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $issuer = $settings->issuer();
        assert($issuer !== '');

        return new ClientRegistrationHandler($register, $responder, $challenger, $issuer);
    }
}
