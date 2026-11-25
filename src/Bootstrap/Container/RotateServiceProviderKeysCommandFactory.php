<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\RotateServiceProviderKeysCommand;
use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Psr\Container\ContainerInterface;

final class RotateServiceProviderKeysCommandFactory
{
    public function __invoke(ContainerInterface $container): RotateServiceProviderKeysCommand
    {
        /** @var RotateServiceProviderKeys $useCase */
        $useCase = $container->get(RotateServiceProviderKeys::class);

        return new RotateServiceProviderKeysCommand($useCase);
    }
}
