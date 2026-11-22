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
 * Someone answering the login page with a passkey, naming no account: the passkey says whose it
 * is.
 */
final readonly class PasskeySignIn
{
    /**
     * @param string|null $loginState       The login page's handle the form carried, if any.
     * @param string      $ceremony         The WebAuthn ceremony's handle the browser holds.
     * @param string      $response         The credential, as the browser's `toJSON()` wrote it.
     * @param string      $clientAddress    Where the request came from, for throttling.
     * @param string|null $currentSessionId The session the browser already holds, if any: replaced on success.
     */
    public function __construct(
        #[\SensitiveParameter] public ?string $loginState,
        #[\SensitiveParameter] public string $ceremony,
        public string $response,
        public string $clientAddress,
        #[\SensitiveParameter] public ?string $currentSessionId = null,
    ) {
    }
}
