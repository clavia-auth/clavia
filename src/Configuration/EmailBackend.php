<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

/**
 * How email leaves this server (`CLAVIA_EMAIL_BACKEND`).
 */
enum EmailBackend: string
{
    /** Logs each message and keeps the last few for `clavia mail outbox`. Development only. */
    case Console = 'console';

    /** Delivers through the configured SMTP server. */
    case Smtp = 'smtp';

    /** Sends nothing, which makes every passwordless connection unusable rather than silently failing. */
    case None = 'none';
}
