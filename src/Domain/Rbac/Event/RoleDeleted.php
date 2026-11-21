<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac\Event;

use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A role was deleted, and taken from everybody holding it.
 */
final readonly class RoleDeleted implements DomainEvent
{
    /**
     * @param Role $role As it was.
     */
    public function __construct(
        public Role $role,
    ) {
    }
}
