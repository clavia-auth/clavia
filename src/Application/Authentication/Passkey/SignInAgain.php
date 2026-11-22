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
 * The session signed in too long ago to change how the account is protected
 * ({@see RecentSignIn}): the person signs in again first, and comes back.
 */
final readonly class SignInAgain
{
}
