<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Secrets\GenerateEncryptionKey;
use Clavia\Adapter\Primary\Cli\GenerateEncryptionKeyCommand;
use Psr\Container\ContainerInterface;

final class GenerateEncryptionKeyCommandFactory
{
    public function __invoke(ContainerInterface $container): GenerateEncryptionKeyCommand
    {
        /** @var GenerateEncryptionKey $generate */
        $generate = $container->get(GenerateEncryptionKey::class);

        return new GenerateEncryptionKeyCommand($generate);
    }
}
