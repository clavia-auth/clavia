<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Event;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An account's password was set from a reset link: the person proved control of the address,
 * and every session of theirs was ended.
 */
final readonly class PasswordReset implements DomainEvent
{
    public function __construct(
        public UserId $userId,
    ) {
    }
}
