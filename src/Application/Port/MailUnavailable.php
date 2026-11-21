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
 * A message could not be handed over for delivery: no mail backend, the server refused
 * the connection or the recipient, the credentials were wrong. The caller tells the
 * person it cannot send right now; what went wrong is for the log.
 */
final class MailUnavailable extends RuntimeException
{
}
