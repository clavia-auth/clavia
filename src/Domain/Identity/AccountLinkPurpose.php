<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

/**
 * What an emailed account link is for. A link for one purpose is refused by every other.
 */
enum AccountLinkPurpose: string
{
    /** Proves the person controls the account's address. */
    case VerifyEmail = 'verify_email';

    /** Lets the person set a new password; doubles as an invitation for an account without one. */
    case ResetPassword = 'reset_password';
}
