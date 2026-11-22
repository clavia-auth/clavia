<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Identity\User;

/**
 * An account as the Management API describes it: the user, and what an operator needs
 * to know about it that lives elsewhere — its second factors.
 */
final readonly class ManagedUser
{
    /** Whether signing in asks for a second factor: a confirmed authenticator app, or a passkey. */
    public bool $mfaEnrolled;

    /**
     * @param bool             $authenticatorApp Whether it has a confirmed authenticator app.
     * @param non-negative-int $passkeyCount     How many passkeys it holds.
     */
    public function __construct(
        public User $user,
        bool $authenticatorApp,
        public int $passkeyCount = 0,
    ) {
        $this->mfaEnrolled = $authenticatorApp || $passkeyCount > 0;
    }
}
