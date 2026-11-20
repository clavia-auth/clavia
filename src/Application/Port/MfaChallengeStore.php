<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\MfaChallenge;

/**
 * Pending second steps of a sign-in ({@see MfaChallenge}), short-lived and keyed by an
 * opaque handle the browser holds in a cookie. Stored as the handle's digest, like a
 * session, so reading the store never yields something a browser could present.
 */
interface MfaChallengeStore
{
    /**
     * @param non-empty-string $handle
     * @param positive-int     $lifetimeSeconds Not extended by anything afterwards.
     */
    public function open(#[\SensitiveParameter] string $handle, MfaChallenge $challenge, int $lifetimeSeconds): void;

    public function find(#[\SensitiveParameter] string $handle): ?MfaChallenge;

    /**
     * Count one wrong answer. At `$maxAttempts` the challenge is destroyed and the person
     * starts again from their password. Atomic: concurrent guesses cannot slip past the
     * limit.
     *
     * @param positive-int $maxAttempts
     *
     * @return bool Whether the challenge survives.
     */
    public function recordFailure(#[\SensitiveParameter] string $handle, int $maxAttempts): bool;

    public function close(#[\SensitiveParameter] string $handle): void;
}
