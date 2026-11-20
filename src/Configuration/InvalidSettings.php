<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

use RuntimeException;

/**
 * The environment describes a configuration Clavia refuses to run with.
 *
 * Raised while the settings are built, so a bad deployment fails when it starts
 * rather than at somebody's first sign-in.
 */
final class InvalidSettings extends RuntimeException
{
}
