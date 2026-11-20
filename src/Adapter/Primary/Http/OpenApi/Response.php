<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

/**
 * One response an operation may give (a Response Object, OpenAPI 3.0 §4.7.17): its
 * headers by lower-cased name, and its content — empty when the response has no body.
 */
final readonly class Response
{
    /**
     * @param array<string, Header> $headers
     */
    public function __construct(
        public array $headers,
        public Content $content,
    ) {
    }
}
