<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use RuntimeException;

/**
 * A WebAuthn response did not verify: malformed, made for another challenge, origin, site,
 * account or purpose, lacking what the ceremony requires, or signed by another key.
 *
 * One exception for every reason, because the person is told one thing whatever it was. The
 * message names the reason for the log and the audit trail, and never holds what the browser
 * sent.
 */
final class PasskeyRejected extends RuntimeException
{
    public static function because(string $reason, ?\Throwable $previous = null): self
    {
        return new self($reason, 0, $previous);
    }
}
