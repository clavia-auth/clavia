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
 * A sign-up the person must correct or give up.
 */
final readonly class SignUpRefused
{
    /**
     * @param string $email  What was typed, to fill the form again.
     * @param string $detail The policy's words for {@see SignUpFailure::PasswordRejected}, or ''.
     */
    public function __construct(
        public SignUpFailure $reason,
        public string $email,
        public string $detail = '',
    ) {
    }
}
