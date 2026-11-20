<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

/**
 * The request was read, and is not what the operation describes: every
 * {@see Violation} found, in path, query, headers, cookies and body.
 */
final class RequestDoesNotMatch extends RequestRejected
{
}
