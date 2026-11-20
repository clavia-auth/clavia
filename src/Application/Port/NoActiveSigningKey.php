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
 * There is no key to sign with.
 *
 * A deployment error, not a request error: nobody created a key, or the only one was
 * removed. It surfaces as a server error the moment a token must be signed, and the
 * message says how to fix it.
 */
final class NoActiveSigningKey extends RuntimeException
{
    public static function create(): self
    {
        return new self('No active signing key. Run `clavia keys:generate` before issuing tokens.');
    }
}
