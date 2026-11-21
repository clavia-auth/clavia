<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Event;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An account was created by an operator.
 */
final readonly class UserCreated implements DomainEvent
{
    public function __construct(
        public User $user,
    ) {
    }
}
