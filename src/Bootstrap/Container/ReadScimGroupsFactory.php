<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Domain\Provisioning\ScimGroupRepository;
use Psr\Container\ContainerInterface;

final class ReadScimGroupsFactory
{
    public function __invoke(ContainerInterface $container): ReadScimGroups
    {
        /** @var ScimGroupRepository $groups */
        $groups = $container->get(ScimGroupRepository::class);

        return new ReadScimGroups($groups);
    }
}
