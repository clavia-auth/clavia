<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

/** The body an operation takes (a Request Body Object, OpenAPI 3.0 §4.7.13). */
final readonly class RequestBody
{
    public function __construct(
        public bool $required,
        public Content $content,
    ) {
    }
}
