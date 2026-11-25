<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\ApiClaims;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Psr\Container\ContainerInterface;

final class ApiClaimsFactory
{
    public function __invoke(ContainerInterface $container): ApiClaims
    {
        /** @var UserRepository $users */
        $users = $container->get(UserRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);

        return new ApiClaims($users, $roles);
    }
}
