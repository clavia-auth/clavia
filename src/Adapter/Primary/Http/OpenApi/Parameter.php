<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Schema\Schema;

/**
 * A parameter an operation takes: in the path, the query, a header or a cookie.
 *
 * Header names compare case-insensitively (RFC 9110 §5.1), so {@see self::$name} of a
 * header parameter is kept lower-cased; every other name is exact.
 */
final readonly class Parameter
{
    public function __construct(
        public string $name,
        public ParameterLocation $location,
        public bool $required,
        public Schema $schema,
        public ParameterStyle $style,
        public bool $explode,
    ) {
    }

    /** `query:page`, `header:x-request-id`: what makes a parameter unique in an operation. */
    public function key(): string
    {
        return $this->location->value . ':' . $this->name;
    }
}
