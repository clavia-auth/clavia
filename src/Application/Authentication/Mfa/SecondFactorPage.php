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
 * What the second-factor page offers: the ways this account can answer, and the origins the
 * sign-in it finishes may end at (the application's redirect origins, for the page's
 * `form-action`).
 */
final readonly class SecondFactorPage
{
    /**
     * @param list<string> $formOrigins
     * @param bool         $authenticatorApp Whether a code from an authenticator app answers.
     * @param bool         $passkey          Whether a passkey does.
     * @param bool         $recoveryCode     Whether a recovery code does.
     * @param bool         $stepUp           Whether a signed-in person is asked for more, rather than signing in.
     * @param string|null  $application      The name of the application asking, when there is one.
     */
    public function __construct(
        public array $formOrigins,
        public bool $authenticatorApp,
        public bool $passkey,
        public bool $recoveryCode = true,
        public bool $stepUp = false,
        public ?string $application = null,
    ) {
    }
}
