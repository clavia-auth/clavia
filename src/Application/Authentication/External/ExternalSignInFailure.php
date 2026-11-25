<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Domain\Authentication\Event\SignInRefusal;

/**
 * Why an external sign-in did not end in a session. The HTTP adapter words each one;
 * nothing the provider said is ever part of the wording.
 */
enum ExternalSignInFailure
{
    /** The provider sent the person back with an error, or without a code. */
    case Cancelled;

    /** The `state` came back to a browser that does not hold it: login CSRF, or another tab. */
    case StartedInAnotherBrowser;

    /** No pending sign-in for that `state`, or one for another provider: expired, or replayed. */
    case Expired;

    /** The code exchange or the identity call did not give a usable answer. */
    case ProviderFailed;

    /** A new identity without an address the provider vouches for: nothing to link or create. */
    case NoVerifiedEmail;

    /** The address belongs to an account here, and linking by address is switched off or ambiguous. */
    case AddressAlreadyUsed;

    /** The account the identity signs in as is deactivated. */
    case AccountDisabled;

    /**
     * The application the sign-in is for does not let its users in through this
     * connection — it stopped while the person was at the provider, or never did.
     */
    case NotAvailable;

    /**
     * The connection lets in only the people a directory provisioned, and this identity is not one
     * (docs/design/scim-provisioning.md §5.4). Worded as {@see self::NotAvailable}.
     */
    case NotProvisioned;

    /** The same failure, as the audit trail names it. */
    public function refusal(): SignInRefusal
    {
        return match ($this) {
            self::Cancelled => SignInRefusal::Cancelled,
            self::StartedInAnotherBrowser => SignInRefusal::StartedInAnotherBrowser,
            self::Expired => SignInRefusal::Expired,
            self::ProviderFailed => SignInRefusal::ProviderFailed,
            self::NoVerifiedEmail => SignInRefusal::NoVerifiedEmail,
            self::AddressAlreadyUsed => SignInRefusal::AddressAlreadyUsed,
            self::AccountDisabled => SignInRefusal::AccountDisabled,
            self::NotAvailable => SignInRefusal::NotAvailable,
            self::NotProvisioned => SignInRefusal::NotProvisioned,
        };
    }
}
