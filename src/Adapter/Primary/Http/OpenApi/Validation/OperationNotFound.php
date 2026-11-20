<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use RuntimeException;

/**
 * The document describes no operation for the request's method and path.
 * {@see self::$pathIsKnown} tells a 405 from a 404.
 */
final class OperationNotFound extends RuntimeException
{
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly bool $pathIsKnown,
    ) {
        parent::__construct(sprintf('The document describes no %s %s.', $method, $path));
    }
}
