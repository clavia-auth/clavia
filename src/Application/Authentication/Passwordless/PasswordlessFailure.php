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
 * Why a passwordless sign-in did not go ahead. The HTTP adapter words each one.
 */
enum PasswordlessFailure
{
    /** What was submitted is not an address, or not a mode: nothing was sent. */
    case InvalidRequest;

    /**
     * The application the sign-in is for does not let its users in by email — or the
     * `email` connection is off, or cannot work because this deployment sends no mail.
     */
    case NotAvailable;

    /** Too many sign-in emails for this address, or from this client address, this hour. */
    case TooManyEmails;

    /** The message could not be handed over for delivery; nothing is pending. */
    case MailUnavailable;

    /**
     * The browser holds no pending code — it never asked, the code expired, or too many
     * wrong ones ended it. The person starts again from the login page.
     */
    case Expired;

    /** The link is unknown, already used or expired. */
    case InvalidLink;

    /** The account the address signs in as is deactivated. */
    case AccountDisabled;
}
