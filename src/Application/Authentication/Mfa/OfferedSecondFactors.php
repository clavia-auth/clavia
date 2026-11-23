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
 * The second factors that may answer a challenge ({@see SecondFactors}).
 */
final readonly class OfferedSecondFactors
{
    public function __construct(
        public bool $authenticatorApp,
        public bool $recoveryCode,
        public bool $passkey,
    ) {
    }

    /** Whether the code field answers: an app's code or a recovery code. */
    public function code(): bool
    {
        return $this->authenticatorApp || $this->recoveryCode;
    }

    public function any(): bool
    {
        return $this->code() || $this->passkey;
    }
}
