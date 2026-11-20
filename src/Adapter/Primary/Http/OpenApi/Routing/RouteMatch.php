<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Routing;

use Clavia\Adapter\Primary\Http\OpenApi\Operation;

/**
 * The operation a request is, with its path parameters as sent (percent-encoded).
 */
final readonly class RouteMatch
{
    /**
     * @param array<string, string> $pathValues
     */
    public function __construct(
        public Operation $operation,
        public array $pathValues,
    ) {
    }
}
