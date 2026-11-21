<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passwordless;

/**
 * A passwordless sign-in that ended without a session, a challenge or a message sent.
 */
final readonly class PasswordlessRefused
{
    public function __construct(public PasswordlessFailure $reason)
    {
    }
}
