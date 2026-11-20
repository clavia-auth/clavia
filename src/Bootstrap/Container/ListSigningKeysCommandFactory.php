<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\ListSigningKeysCommand;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Psr\Container\ContainerInterface;

final class ListSigningKeysCommandFactory
{
    public function __invoke(ContainerInterface $container): ListSigningKeysCommand
    {
        /** @var ListSigningKeys $useCase */
        $useCase = $container->get(ListSigningKeys::class);

        return new ListSigningKeysCommand($useCase);
    }
}
