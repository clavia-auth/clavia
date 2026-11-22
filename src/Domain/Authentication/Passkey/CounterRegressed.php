<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use RuntimeException;

/**
 * A passkey's signature counter did not grow, which can mean its authenticator was cloned
 * (WebAuthn Level 3 §6.1.3). The sign-in is refused and audited.
 *
 * Synced passkeys always report zero and are unaffected: a counter that is zero and was
 * zero is not a regression.
 */
final class CounterRegressed extends RuntimeException
{
    public static function between(int $stored, int $presented): self
    {
        return new self(sprintf('The signature counter went from %d to %d.', $stored, $presented));
    }
}
