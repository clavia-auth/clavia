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
 * One-way hashing for what a person or an operator chose: user passwords and the
 * secrets of confidential clients.
 *
 * Deliberately slow and salted, unlike {@see \Clavia\Domain\Shared\Digest}, because
 * these values come from a small guess space. The stored string is self-describing
 * (algorithm, cost, salt), so the cost can be raised without a migration.
 */
interface PasswordHasher
{
    /**
     * @return non-empty-string The hash to store.
     *
     * @throws SecretNotHashable When the algorithm cannot represent the secret faithfully.
     */
    public function hash(#[\SensitiveParameter] string $secret): string;

    /**
     * Whether `$secret` is the one `$hash` was made from.
     *
     * Never throws: a malformed or foreign hash, or a secret the algorithm cannot
     * represent, is simply not a match — a bad row must not turn a login into a 500.
     */
    public function verify(#[\SensitiveParameter] string $secret, string $hash): bool;

    /** Whether a hash that just verified should be replaced by a fresh one at today's cost. */
    public function needsRehash(string $hash): bool;
}
