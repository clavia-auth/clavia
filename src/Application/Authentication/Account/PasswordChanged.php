<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

/**
 * A password set from a reset link. Every session was ended; the person signs in next.
 */
final readonly class PasswordChanged
{
    /**
     * @param non-empty-string      $email      The account's address, to prefill the login form.
     * @param non-empty-string|null $loginState The authorization request to return to, when it is still pending.
     */
    public function __construct(
        public string $email,
        public ?string $loginState,
    ) {
    }
}
