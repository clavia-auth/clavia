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

/** A header a response declares (a Header Object, OpenAPI 3.0 §4.7.21): `simple` style. */
final readonly class Header
{
    public function __construct(
        public string $name,
        public bool $required,
        public Schema $schema,
    ) {
    }
}
