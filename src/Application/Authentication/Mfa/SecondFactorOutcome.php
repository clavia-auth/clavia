<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Authentication\SignIn\SignedIn;

/**
 * What came of a second-factor answer: {@see SignedIn}, {@see SecondFactorRejected} (try
 * again) or {@see ChallengeGone} (start again from the password).
 */
interface SecondFactorOutcome
{
}
