<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

/**
 * The code was wrong — or the account can no longer sign in — and the challenge has
 * attempts left. One outcome for every reason, as for a password.
 */
final readonly class SecondFactorRejected implements SecondFactorOutcome
{
}
