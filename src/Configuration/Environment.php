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
 * The kind of deployment this process is part of (`CLAVIA_ENV`).
 *
 * Several settings are refused outside {@see self::Development}, and a few defaults
 * only make sense there.
 */
enum Environment: string
{
    case Development = 'development';
    case Staging = 'staging';
    case Production = 'production';
}
