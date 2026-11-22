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
 * Whose account this is, whether its authenticator app is on, its passkeys, and the recovery
 * codes left for either.
 */
final readonly class MfaStatus
{
    /**
     * @param non-negative-int $recoveryCodesLeft
     * @param int|null         $passkeys          How many passkeys the account holds; null when passkeys are off.
     */
    public function __construct(
        public string $email,
        public bool $enabled,
        public int $recoveryCodesLeft,
        public ?int $passkeys = null,
    ) {
    }
}
