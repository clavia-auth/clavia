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
 * A role with its permissions described, as `GET /api/v1/roles/{role_id}` shows it.
 */
final readonly class DescribedRole
{
    /**
     * @param list<DescribedPermission> $permissions By API identifier, then value.
     */
    public function __construct(
        public Role $role,
        public array $permissions,
    ) {
    }
}
