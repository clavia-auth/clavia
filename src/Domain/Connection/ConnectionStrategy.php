<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

/**
 * How a connection signs people in.
 */
enum ConnectionStrategy: string
{
    /** A pool of accounts with passwords, held by this server. Several may exist. */
    case Database = 'database';

    /**
     * One of the providers the code implements (Google, GitHub), its credentials from the
     * deployment's settings. Built in: switched on and off, never created or deleted.
     */
    case Social = 'social';

    /** Any OpenID Connect provider, registered by an operator from its issuer. */
    case Oidc = 'oidc';

    /** Signs people in at another party rather than here. */
    public function isExternal(): bool
    {
        return $this !== self::Database;
    }
}
