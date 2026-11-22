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
 * Why a sign-up was refused: each one a reason the person can act on, none of them saying
 * whether the address has an account — except {@see self::AddressTaken}, given only by a pool
 * that signs new accounts in at once and so cannot hide it.
 */
enum SignUpFailure
{
    /** Not an email address. */
    case InvalidEmail;

    /** The password does not meet the policy; the refusal carries the policy's words. */
    case PasswordRejected;

    /** The application offers no sign-up, or the pool needs mail this deployment cannot send. */
    case NotAvailable;

    /** Too many accounts created from this client address in the last hour. */
    case TooManySignUps;

    /** The address has an account in this pool, which does not require a verified address. */
    case AddressTaken;
}
