<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

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
}
