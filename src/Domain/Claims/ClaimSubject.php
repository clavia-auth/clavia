<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use Clavia\Domain\Identity\User;

/**
 * Who a token is about, as the sources read it: the account, and the names of the roles that
 * apply (for an API, those holding a permission on it).
 */
final readonly class ClaimSubject
{
    /** @param list<string> $roles */
    public function __construct(
        public User $user,
        public array $roles,
    ) {
    }
}
