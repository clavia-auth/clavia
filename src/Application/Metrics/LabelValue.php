<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Metrics;

/**
 * A label's value as it is kept and exposed: letters, digits and `_ . : + -`, at most 64 of them.
 * Anything else becomes `_`, and an empty value is `none`. Callers pass bounded values (a grant
 * type, a route's name); this keeps a value that is not from breaking the format or the storage.
 */
final class LabelValue
{
    private const int MAX_LENGTH = 64;

    private function __construct()
    {
    }

    public static function of(string $value): string
    {
        $value = substr((string) preg_replace('/[^A-Za-z0-9_.:+\-]/', '_', $value), 0, self::MAX_LENGTH);

        return $value === '' ? 'none' : $value;
    }
}
