<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management;

use RuntimeException;

/**
 * The operation contradicts the state it would change: deleting the client or the
 * account the caller is acting as, for one.
 */
final class Conflict extends RuntimeException
{
}
