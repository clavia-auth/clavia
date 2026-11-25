<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Provisioning\Users\PatchScimUser;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Application\Provisioning\Users\ReplaceScimUser;
use Psr\Container\ContainerInterface;

final class PatchScimUserFactory
{
    public function __invoke(ContainerInterface $container): PatchScimUser
    {
        /** @var ReadScimUsers $read */
        $read = $container->get(ReadScimUsers::class);
        /** @var ReplaceScimUser $replace */
        $replace = $container->get(ReplaceScimUser::class);

        return new PatchScimUser($read, $replace);
    }
}
