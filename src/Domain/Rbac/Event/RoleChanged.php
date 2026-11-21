<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac\Event;

use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A role changed.
 */
final readonly class RoleChanged implements DomainEvent
{
    /**
     * @param list<string> $changed What changed, by name — never to what.
     */
    public function __construct(
        public RoleId $roleId,
        public array $changed,
    ) {
    }
}
