<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

/**
 * A new password the policy refused. The link is kept, so the person can try another.
 */
final readonly class PasswordRejected
{
    public function __construct(
        public PasswordRefusal $reason,
    ) {
    }
}
