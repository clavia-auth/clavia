<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection;

use Clavia\Application\Port\IdentityProvider;
use Clavia\Domain\Connection\Connection;

/**
 * A connection that is switched on and can work — with, for an external one, the provider
 * behind it.
 */
final readonly class UsableConnection
{
    /**
     * @param IdentityProvider|null $provider Null for a connection that signs people in here — a pool, the
     *                                       passwordless one — and only for one.
     */
    public function __construct(
        public Connection $connection,
        public ?IdentityProvider $provider,
    ) {
    }
}
