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
 * Someone typing an email and a password on the login page.
 */
final readonly class PasswordSignIn
{
    /**
     * @param string      $clientAddress    Where the request came from, for throttling.
     * @param string|null $loginState       The opaque handle of the pending authorization request, if any.
     * @param string|null $currentSessionId The session the browser already holds, if any — ended on success.
     */
    public function __construct(
        public string $email,
        #[\SensitiveParameter] public string $password,
        public string $clientAddress,
        #[\SensitiveParameter] public ?string $loginState = null,
        #[\SensitiveParameter] public ?string $currentSessionId = null,
    ) {
    }
}
