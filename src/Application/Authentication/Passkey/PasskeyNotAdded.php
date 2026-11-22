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
 * Why a registration response did not become a passkey. The person is told little more than
 * "start again": which of these it was is for the log, not for a page.
 */
enum PasskeyNotAdded
{
    /** The ceremony is unknown, spent, expired, someone else's, or for something else. */
    case CeremonyGone;

    /** The response did not verify. */
    case Rejected;

    /** The credential is already registered, on this account or another. */
    case AlreadyRegistered;

    /** The name the person chose cannot be a passkey's name. */
    case InvalidName;
}
