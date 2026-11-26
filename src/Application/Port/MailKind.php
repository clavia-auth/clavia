<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * The mails this server sends (docs/design/translated-sign-in-pages.md §4): which one, never its
 * words, which the mailer takes from the catalogue in the mail's language.
 */
enum MailKind
{
    /** A link to confirm the address an account signed up with. */
    case Verification;
    /** A link to choose a new password. */
    case Reset;
    /** A link to choose the password of an account an operator created without one. */
    case Invitation;
    /** The notice that someone tried to sign up with an address that already has an account. */
    case AddressTaken;
    /** The notice that a second factor was set up on the way to an application. */
    case SecondFactorEnrolled;
    /** A six-digit code to sign in with. */
    case PasswordlessCode;
    /** A link to sign in with. */
    case PasswordlessLink;
}
