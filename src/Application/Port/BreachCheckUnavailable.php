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
 * The breached-password corpus could not be asked: the service was unreachable, refused
 * by the outbound policy, or answered something else than a list. What went wrong is for
 * the log, which the adapter writes; the caller decides what follows.
 */
final class BreachCheckUnavailable extends RuntimeException
{
}
