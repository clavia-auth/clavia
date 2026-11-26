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
 * Why a password was refused, for the page to word in the person's language: never the policy's own
 * English, which the Management API still shows its callers.
 */
enum PasswordRefusal
{
    /** Shorter than `PasswordPolicy::MIN_LENGTH` characters, longer than its `MAX_BYTES`, or not text. */
    case Policy;
    /** Known to have leaked (Pwned Passwords): `CLAVIA_BREACHED_PASSWORD_CHECK`. */
    case Breached;
}
