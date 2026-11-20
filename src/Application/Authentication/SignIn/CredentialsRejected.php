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
 * The attempt did not authenticate anyone.
 *
 * Deliberately one outcome for every reason — an unknown account, a wrong password, a
 * deactivated account, one without a password, a throttled one. Each distinction shown
 * to the caller would be a free oracle on who has an account here.
 */
final readonly class CredentialsRejected implements SignInOutcome
{
}
