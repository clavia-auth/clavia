<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;

/**
 * WebAuthn ceremonies in progress ({@see WebAuthnChallenge}), short-lived and keyed by an opaque
 * handle the browser holds in a cookie. Stored as the handle's digest, like a session, so reading
 * the store never yields something a browser could present.
 */
interface WebAuthnChallengeStore
{
    /**
     * @param non-empty-string $handle
     * @param positive-int     $lifetimeSeconds Not extended by anything afterwards.
     */
    public function open(
        #[\SensitiveParameter] string $handle,
        WebAuthnChallenge $challenge,
        int $lifetimeSeconds,
    ): void;

    /**
     * Take the challenge, once: whoever claims it first holds it, and it is gone whether the
     * response that follows is good or bad. Unknown, spent, expired and someone else's are all
     * null.
     */
    public function claim(#[\SensitiveParameter] string $handle): ?WebAuthnChallenge;
}
