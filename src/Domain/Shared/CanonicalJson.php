<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use JsonException;
use stdClass;

/**
 * One encoding for a JSON value whatever order its objects' keys came in: keys sorted in byte
 * order at every level, lists in their own order, slashes and Unicode unescaped, `1.0` kept a
 * float. PostgreSQL's `jsonb` reorders keys when it stores a value, so a value written and read
 * back compares equal only in this form.
 */
final readonly class CanonicalJson
{
    private const int FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION
        | JSON_THROW_ON_ERROR;

    private function __construct()
    {
    }

    /**
     * @param mixed $value A decoded JSON value (objects as `stdClass`).
     *
     * @return non-empty-string
     *
     * @throws JsonException
     */
    public static function encode(mixed $value): string
    {
        return json_encode(self::sorted($value), self::FLAGS);
    }

    private static function sorted(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $members = get_object_vars($value);
            ksort($members, SORT_STRING);
            $sorted = new stdClass();
            /** @var mixed $item */
            foreach ($members as $key => $item) {
                /** @psalm-suppress MixedAssignment */
                $sorted->{(string) $key} = self::sorted($item);
            }

            return $sorted;
        }
        if (is_array($value)) {
            return array_map(self::sorted(...), $value);
        }

        return $value;
    }
}
