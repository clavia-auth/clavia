<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\BreachedPasswords;

use Clavia\Application\Port\BreachedPasswords;

/**
 * The check turned off (`CLAVIA_BREACHED_PASSWORD_CHECK=false`, the default): no
 * password is known to have leaked, and nothing leaves the server.
 */
final readonly class NoBreachedPasswords implements BreachedPasswords
{
    #[\Override]
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        return false;
    }
}
