<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\Clock;

/**
 * Whether a session signed in recently enough to change how its account is protected
 * (docs/design/passkeys.md §6.1, §12): adding, renaming or removing a passkey.
 *
 * A browser left signed in is not proof that the person at it is the account's owner. Past the
 * window (`CLAVIA_PASSKEY_REAUTH_WINDOW`) they sign in again first, and the sign-in that follows
 * is the fresh proof.
 */
final readonly class RecentSignIn
{
    /**
     * @param positive-int $windowSeconds
     */
    public function __construct(
        private Clock $clock,
        private int $windowSeconds,
    ) {
    }

    public function allows(Session $session): bool
    {
        return $this->clock->now()->getTimestamp() - $session->authenticatedAt->getTimestamp() <= $this->windowSeconds;
    }
}
