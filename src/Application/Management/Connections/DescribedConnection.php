<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Domain\Connection\Connection;

/**
 * A connection, with what only the running server knows: whether it can work.
 */
final readonly class DescribedConnection
{
    /**
     * @param bool $configured Whether it could work if switched on: always for a pool; for an
     *                         external connection, when the deployment can build its provider.
     * @param bool $usable     Switched on and configured: what the login page actually offers.
     */
    public function __construct(
        public Connection $connection,
        public bool $configured,
        public bool $usable,
    ) {
    }
}
