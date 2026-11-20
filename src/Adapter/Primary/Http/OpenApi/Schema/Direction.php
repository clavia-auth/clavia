<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

/**
 * Which way an instance travels, for `readOnly` and `writeOnly` (OpenAPI 3.0 §4.7.24):
 * a read-only property is never sent in a request, a write-only one never in a
 * response, and neither is required in the direction it does not travel.
 */
enum Direction
{
    case Request;
    case Response;
}
