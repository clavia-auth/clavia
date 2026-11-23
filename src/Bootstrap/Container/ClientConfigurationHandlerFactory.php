<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\OAuth2\ClientConfigurationHandler;
use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Application\Clients\Registration\DeleteClientConfiguration;
use Clavia\Application\Clients\Registration\ReadClientConfiguration;
use Clavia\Application\Clients\Registration\UpdateClientConfiguration;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;

final class ClientConfigurationHandlerFactory
{
    public function __invoke(ContainerInterface $container): ClientConfigurationHandler
    {
        /** @var ReadClientConfiguration $read */
        $read = $container->get(ReadClientConfiguration::class);
        /** @var UpdateClientConfiguration $update */
        $update = $container->get(UpdateClientConfiguration::class);
        /** @var DeleteClientConfiguration $delete */
        $delete = $container->get(DeleteClientConfiguration::class);
        /** @var OAuth2Responder $responder */
        $responder = $container->get(OAuth2Responder::class);
        /** @var BearerChallenger $challenger */
        $challenger = $container->get(BearerChallenger::class);
        /** @var ResponseFactoryInterface $responses */
        $responses = $container->get(ResponseFactoryInterface::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        $issuer = $settings->issuer();
        assert($issuer !== '');

        return new ClientConfigurationHandler(
            $read,
            $update,
            $delete,
            $responder,
            $challenger,
            $responses,
            $issuer,
        );
    }
}
