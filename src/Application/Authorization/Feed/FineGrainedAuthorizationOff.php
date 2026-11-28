<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

use RuntimeException;

/**
 * Fine-grained authorization is off on this server: `CLAVIA_FGA_URL` names no decision engine.
 */
final class FineGrainedAuthorizationOff extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Fine-grained authorization is off on this server: it names no decision engine.');
    }
}
