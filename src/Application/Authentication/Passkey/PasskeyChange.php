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
 * What became of renaming or removing a passkey.
 */
enum PasskeyChange
{
    case Done;

    /** No such passkey on this account: never there, already removed, or someone else's. */
    case NotFound;

    /** The new name cannot be a passkey's name. */
    case InvalidName;
}
