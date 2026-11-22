<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

/**
 * Why a sign-in was refused — said to the audit trail, never to the person, who sees one
 * message whatever the reason (a different answer would tell an attacker which
 * addresses have accounts).
 */
enum SignInRefusal: string
{
    /** Too many recent failures for the account or the client address. */
    case Throttled = 'throttled';

    /** No usable account with a password at that address in the application's pools. */
    case UnknownAccount = 'unknown_account';

    case WrongPassword = 'wrong_password';

    /** The authenticator app's code or the recovery code did not match. */
    case WrongSecondFactor = 'wrong_second_factor';

    /** The code sent by email did not match. */
    case WrongCode = 'wrong_code';

    /** The person turned the provider down, or the provider reported an error. */
    case Cancelled = 'cancelled';

    /** The provider's answer reached a browser other than the one that went there. */
    case StartedInAnotherBrowser = 'started_in_another_browser';

    /** The sign-in took too long, or its state was already used. */
    case Expired = 'expired';

    /** The provider could not be reached, or its answer did not check out. */
    case ProviderFailed = 'provider_failed';

    /** The provider vouched for no address, and one is needed to make an account. */
    case NoVerifiedEmail = 'no_verified_email';

    /** The address belongs to another account and could not be linked. */
    case AddressAlreadyUsed = 'address_already_used';

    case AccountDisabled = 'account_disabled';

    /** The right password, for an account whose pool requires a verified address it has not proved. */
    case EmailNotVerified = 'email_not_verified';

    /** The application does not enable that connection, or it cannot work. */
    case NotAvailable = 'not_available';
}
