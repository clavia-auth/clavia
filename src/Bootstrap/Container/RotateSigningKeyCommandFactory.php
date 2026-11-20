<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Cli\RotateSigningKeyCommand;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Psr\Container\ContainerInterface;

final class RotateSigningKeyCommandFactory
{
    public function __invoke(ContainerInterface $container): RotateSigningKeyCommand
    {
        /** @var RotateSigningKey $useCase */
        $useCase = $container->get(RotateSigningKey::class);

        return new RotateSigningKeyCommand($useCase);
    }
}
