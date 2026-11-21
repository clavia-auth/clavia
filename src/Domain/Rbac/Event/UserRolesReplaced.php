<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac\Event;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * Everything an account holds was replaced by a list.
 */
final readonly class UserRolesReplaced implements DomainEvent
{
    /**
     * @param list<RoleId> $roles What it holds now.
     */
    public function __construct(
        public UserId $userId,
        public array $roles,
    ) {
    }
}
