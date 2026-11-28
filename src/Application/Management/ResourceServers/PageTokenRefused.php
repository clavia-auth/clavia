<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use RuntimeException;

/**
 * A page token the decision engine does not take: not one a previous page gave, or another store's.
 */
final class PageTokenRefused extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The page token is not one a previous page gave.');
    }
}
