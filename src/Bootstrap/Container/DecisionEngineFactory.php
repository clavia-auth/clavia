<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Authorization\NoDecisionEngine;
use Clavia\Adapter\Secondary\Authorization\OpenFgaDecisionEngine;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Configuration\Settings;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * OpenFGA when `CLAVIA_FGA_URL` names it; otherwise fine-grained authorization is off, and an
 * engine that answers nothing stands in. Building it reaches nothing: OpenFGA is called when a
 * question is asked.
 */
final class DecisionEngineFactory
{
    public function __invoke(ContainerInterface $container): DecisionEngine
    {
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);
        if ($settings->fgaUrl === null || $settings->fgaApiKey === null) {
            return new NoDecisionEngine();
        }

        /** @var ClientInterface $http */
        $http = $container->get(FgaHttpClientFactory::SERVICE);
        /** @var RequestFactoryInterface $requests */
        $requests = $container->get(RequestFactoryInterface::class);
        /** @var StreamFactoryInterface $streams */
        $streams = $container->get(StreamFactoryInterface::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new OpenFgaDecisionEngine($http, $requests, $streams, $settings->fgaUrl, $settings->fgaApiKey, $logger);
    }
}
