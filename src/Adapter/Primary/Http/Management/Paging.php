<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;
use LogicException;

/**
 * The `page`, `per_page` and `q` query parameters every list operation takes, as a
 * {@see PageRequest}. The contract has already typed and bounded them; absent ones take
 * its defaults.
 */
final class Paging
{
    private function __construct()
    {
    }

    /**
     * @throws InvalidValue
     */
    public static function fromRequest(ManagementRequest $request): PageRequest
    {
        return PageRequest::of(
            self::integer($request->query('page'), 'page', 1),
            self::integer($request->query('per_page'), 'per_page', 50),
            self::string($request->query('q')),
        );
    }

    private static function integer(mixed $value, string $name, int $default): int
    {
        return match (true) {
            $value === null => $default,
            is_int($value) => $value,
            default => throw new LogicException(sprintf("The contract lets '%s' through as a non-integer.", $name)),
        };
    }

    private static function string(mixed $value): string
    {
        return match (true) {
            $value === null => '',
            is_string($value) => $value,
            default => throw new LogicException("The contract lets 'q' through as a non-string."),
        };
    }
}
