<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

/**
 * Why a passkey did not answer a ceremony. The person is told one thing; this is for the trail.
 */
enum PasskeyRefusal
{
    /** No passkey has that credential, or it is not the account's the ceremony expects. */
    case Unknown;

    /** The response did not verify against the passkey. */
    case Rejected;

    /** The signature counter did not grow: the authenticator may have been cloned. */
    case CounterRegressed;

    /** Another use of the passkey moved its counter first. */
    case Raced;
}
