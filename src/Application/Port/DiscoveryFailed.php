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
 * The issuer did not answer discovery with something usable. The message says what was
 * wrong, in this server's words, for the operator registering the connection — never
 * anything the remote server sent.
 */
final class DiscoveryFailed extends RuntimeException
{
}
