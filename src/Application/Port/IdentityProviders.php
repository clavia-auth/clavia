<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Connection\Connection;

/**
 * The providers behind external connections, as this deployment can build them.
 */
interface IdentityProviders
{
    /**
     * The provider behind `$connection`, or null when it cannot work: a database
     * connection (there is no provider), a social connection the code does not implement or
     * the deployment has no credentials for, an OIDC connection whose secret cannot be
     * decrypted. A button that fails is worse than no button.
     *
     * Whether the connection is switched on is not asked here: see
     * {@see \Clavia\Application\Connection\ConnectionAccess}.
     */
    public function for(Connection $connection): ?IdentityProvider;
}
