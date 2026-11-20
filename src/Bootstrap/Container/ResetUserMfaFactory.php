<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Management\Users\ResetUserMfa;
use Clavia\Domain\Identity\UserRepository;
use Psr\Container\ContainerInterface;

final class ResetUserMfaFactory
{
    public function __invoke(ContainerInterface $container): ResetUserMfa
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var DisableMfa $disable */
        $disable = $container->get(DisableMfa::class);

        return new ResetUserMfa($users, $disable);
    }
}
