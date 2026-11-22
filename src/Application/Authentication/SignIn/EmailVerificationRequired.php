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
 * The right password, for an account whose pool requires a verified address it has not
 * proved yet. No session: a fresh verification link was mailed instead (within the send
 * limit), and the person signs in once they have followed it.
 *
 * Only ever answered once the password has verified, so it says nothing to someone who does
 * not know it.
 */
final readonly class EmailVerificationRequired implements SignInOutcome
{
    /**
     * @param non-empty-string $email The account's address, to say where the link went.
     */
    public function __construct(
        public string $email,
    ) {
    }
}
