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
 * There is no challenge to answer — it expired, was used up by wrong answers, or never
 * existed — so there is nothing to retry: the person starts again from their password.
 */
final readonly class ChallengeGone implements SecondFactorOutcome
{
}
