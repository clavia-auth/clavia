<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Application\OAuth2\Token\UserScope;
use Clavia\Configuration\Settings;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\ScopeSet;
use Psr\Container\ContainerInterface;

final class UserScopeFactory
{
    public function __invoke(ContainerInterface $container): UserScope
    {
        /** @var ResourceServerRepository $resourceServers */
        $resourceServers = $container->get(ResourceServerRepository::class);
        /** @var RoleRepository $roles */
        $roles = $container->get(RoleRepository::class);
        /** @var Settings $settings */
        $settings = $container->get(Settings::class);

        return new UserScope($resourceServers, $roles, ScopeSet::fromString(implode(' ', $settings->scopesSupported)));
    }
}
