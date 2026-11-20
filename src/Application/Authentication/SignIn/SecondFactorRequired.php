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
 * The first factor passed and the account has a second one: no session yet. The browser
 * gets the handle of an {@see \Clavia\Domain\Authentication\MfaChallenge} instead, and
 * finishes at the second-factor page.
 */
final readonly class SecondFactorRequired implements SignInOutcome
{
    /**
     * @param non-empty-string $challenge The challenge's handle, to hand to the browser once.
     */
    public function __construct(#[\SensitiveParameter] public string $challenge)
    {
    }
}
