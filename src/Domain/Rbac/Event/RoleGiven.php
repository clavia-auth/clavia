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
 * Somebody was given a role they did not hold.
 */
final readonly class RoleGiven implements DomainEvent
{
    public function __construct(
        public RoleId $roleId,
        public UserId $userId,
    ) {
    }
}
