<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use LogicException;

/**
 * The OpenAPI document cannot be used: it is malformed, refers to something it does not
 * define, or relies on a feature this validator does not implement.
 *
 * A defect of the document, found when it is loaded rather than on the first request
 * that happens to reach the broken part. The message names the place, as a JSON pointer
 * into the document (`#/paths/~1users/get/parameters/0`).
 */
final class InvalidDocument extends LogicException
{
    public static function at(string $pointer, string $problem): self
    {
        return new self(sprintf('#%s: %s', $pointer, $problem));
    }
}
