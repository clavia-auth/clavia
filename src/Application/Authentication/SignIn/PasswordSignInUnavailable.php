<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

/**
 * The application the sign-in is for lets its users in through no pool: a password
 * cannot sign anybody in to it, however the form was posted. Decided before any
 * password is looked at.
 */
final readonly class PasswordSignInUnavailable implements SignInOutcome
{
}
