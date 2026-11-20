<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Counts recent failures per subject — an account, a client address — within a window.
 *
 * Storage never holds a subject in plaintext: a list of which addresses tried which
 * accounts would be a small directory of who signs in from where.
 */
interface AttemptCounter
{
    /**
     * Failures counted for the subject within its current window; zero when none.
     */
    public function count(string $subject): int;

    /**
     * Count one more failure and restart the window, so sustained guessing stays
     * locked out instead of recovering while the attack is still running.
     *
     * @param positive-int $windowSeconds
     */
    public function increment(string $subject, int $windowSeconds): void;

    public function reset(string ...$subjects): void;
}
