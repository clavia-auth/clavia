<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Authentication\Mfa\SecondFactorOutcome;

/**
 * The person is authenticated and has a session — by password alone, or once a second
 * factor completed what the password started.
 */
final readonly class SignedIn implements SignInOutcome, SecondFactorOutcome
{
    /**
     * @param non-empty-string $sessionId The new session identifier, to hand to the browser once.
     * @param string           $nextUrl   Where to send the browser: a validated local path.
     */
    public function __construct(
        #[\SensitiveParameter] public string $sessionId,
        public string $nextUrl,
    ) {
    }
}
