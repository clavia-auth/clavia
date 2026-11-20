<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Roles;

use Clavia\Domain\Rbac\Role;

/**
 * A permission somebody holds, and every role through which they hold it.
 *
 * All of them, because several roles can grant the same permission and taking one away
 * does not necessarily take the permission — which is precisely what surprises people.
 */
final readonly class EffectivePermission
{
    /**
     * @param non-empty-list<Role> $roles By name.
     */
    public function __construct(
        public DescribedPermission $permission,
        public array $roles,
    ) {
    }
}
