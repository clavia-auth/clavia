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
 * No usable encryption key is configured.
 *
 * There is deliberately no fallback to unencrypted storage: a silently weaker mode is
 * one nobody notices they are running. Callers refuse instead.
 */
final class EncryptionUnavailable extends RuntimeException
{
}
