<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Http;

use RuntimeException;

/**
 * A URL this server will not fetch. The message names what was refused and why, and is
 * fit for the operator who supplied it.
 */
final class OutboundUrlRefused extends RuntimeException
{
}
