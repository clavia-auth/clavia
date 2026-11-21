<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

/**
 * What a device's poll of the token endpoint finds (RFC 8628 §3.5).
 */
enum DevicePoll
{
    /** Nobody has decided yet: `authorization_pending`. */
    case Pending;

    /** Polled more often than the interval allows: `slow_down`, and the interval grows. */
    case SlowDown;

    /** The person refused: `access_denied`. */
    case Denied;

    /** The code ran out before it was redeemed: `expired_token`. */
    case Expired;

    /** The person allowed it: the token can be issued. */
    case Approved;
}
