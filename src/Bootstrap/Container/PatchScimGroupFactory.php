<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Provisioning\Groups\PatchScimGroup;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Application\Provisioning\Groups\ReplaceScimGroup;
use Psr\Container\ContainerInterface;

final class PatchScimGroupFactory
{
    public function __invoke(ContainerInterface $container): PatchScimGroup
    {
        /** @var ReadScimGroups $read */
        $read = $container->get(ReadScimGroups::class);
        /** @var ReplaceScimGroup $replace */
        $replace = $container->get(ReplaceScimGroup::class);

        return new PatchScimGroup($read, $replace);
    }
}
