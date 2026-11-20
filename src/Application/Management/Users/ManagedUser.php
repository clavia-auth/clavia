<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Identity\User;

/**
 * An account as the Management API describes it: the user, and what an operator needs
 * to know about it that lives elsewhere — whether it has a confirmed second factor.
 */
final readonly class ManagedUser
{
    public function __construct(
        public User $user,
        public bool $mfaEnrolled,
    ) {
    }
}
