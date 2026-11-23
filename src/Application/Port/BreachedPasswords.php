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
 * Whether a password is known to have leaked: NIST SP 800-63B §5.1.1.2 asks a verifier
 * to refuse a password found in a corpus of compromised ones.
 *
 * The question carries the password itself; how much of it leaves the server is the
 * adapter's to keep to a minimum (a hash prefix, k-anonymity).
 */
interface BreachedPasswords
{
    /**
     * @throws BreachCheckUnavailable When the corpus cannot be asked right now.
     */
    #[\NoDiscard]
    public function isBreached(#[\SensitiveParameter] string $password): bool;
}
