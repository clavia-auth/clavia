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
 * What ended a session before its time.
 */
enum SessionEndReason: string
{
    /** The person signed out at `/auth/logout`. */
    case SignedOut = 'signed_out';

    /** An application's logout request (RP-Initiated Logout) ended it. */
    case RpInitiatedLogout = 'rp_initiated_logout';

    /** Every session of the account was ended — by an operator, or with the account. */
    case EndedEverywhere = 'ended_everywhere';

    /** An operator ended this one session by its `sid`. */
    case EndedByOperator = 'ended_by_operator';

    /** Whether the person themself ended it, rather than somebody acting on the account. */
    public function byThePerson(): bool
    {
        return $this === self::SignedOut || $this === self::RpInitiatedLogout;
    }
}
