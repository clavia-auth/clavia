<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\PasswordlessChallenge;

/**
 * Pending passwordless sign-ins ({@see PasswordlessChallenge}), short-lived and keyed by
 * an opaque handle: the cookie of the browser that asked for a code, or the secret of a
 * link. Stored as the handle's digest, so reading the store yields neither.
 */
interface PasswordlessChallengeStore
{
    /**
     * @param non-empty-string $handle
     * @param positive-int     $lifetimeSeconds Not extended by anything afterwards.
     */
    public function open(
        #[\SensitiveParameter] string $handle,
        PasswordlessChallenge $challenge,
        int $lifetimeSeconds,
    ): void;

    public function find(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge;

    /**
     * Count one wrong code. At `$maxAttempts` the challenge is destroyed and the person
     * asks for a new one. Atomic, and the lifetime is kept: guessing neither slips past
     * the limit nor buys time.
     *
     * @param positive-int $maxAttempts
     *
     * @return bool Whether the challenge survives.
     */
    public function recordFailure(#[\SensitiveParameter] string $handle, int $maxAttempts): bool;

    /**
     * Take the challenge out of the store: of two requests presenting the same handle, one
     * gets it and the other null — a code or a link signs in once.
     */
    public function claim(#[\SensitiveParameter] string $handle): ?PasswordlessChallenge;
}
