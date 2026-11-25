<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\GenerateServiceProviderKeysCommand;
use Clavia\Application\Connection\Saml\GenerateServiceProviderKeys;
use Psr\Container\ContainerInterface;

final class GenerateServiceProviderKeysCommandFactory
{
    public function __invoke(ContainerInterface $container): GenerateServiceProviderKeysCommand
    {
        /** @var GenerateServiceProviderKeys $useCase */
        $useCase = $container->get(GenerateServiceProviderKeys::class);

        return new GenerateServiceProviderKeysCommand($useCase);
    }
}
