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
 * Someone answering the second-factor page: a TOTP code or a recovery code.
 */
final readonly class SecondFactorAttempt
{
    /**
     * @param string      $challenge        The challenge handle the browser holds.
     * @param string      $clientAddress    Where the request came from, for throttling.
     * @param string|null $currentSessionId The session the browser already holds, if any — ended on success.
     */
    public function __construct(
        #[\SensitiveParameter] public string $challenge,
        #[\SensitiveParameter] public string $code,
        public string $clientAddress,
        #[\SensitiveParameter] public ?string $currentSessionId = null,
    ) {
    }
}
