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
 * One way an instance fails its schema: where (an RFC 6901 pointer into the instance,
 * `''` for the instance itself) and why.
 *
 * The message states the constraint, never the value at fault: the value may be a
 * password, and an error is logged and displayed in more places than the request was.
 */
final readonly class SchemaViolation
{
    public function __construct(
        public string $pointer,
        public string $message,
    ) {
    }
}
