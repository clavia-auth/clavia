<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

use stdClass;

/**
 * The JSON data model as PHP holds it once decoded without associative arrays: `null`,
 * `bool`, `int`, `float`, `string`, lists, and `stdClass` objects — so that `{}` and
 * `[]` stay different things.
 */
final class JsonValue
{
    private function __construct()
    {
    }

    /**
     * JSON Schema equality, for `enum` and `uniqueItems`: numbers by value (`1` equals
     * `1.0`), lists item by item, objects member by member whatever their order.
     */
    public static function equals(mixed $a, mixed $b): bool
    {
        if ((is_int($a) || is_float($a)) && (is_int($b) || is_float($b))) {
            return $a == $b;
        }
        if (is_array($a) && is_array($b)) {
            if (count($a) !== count($b)) {
                return false;
            }
            foreach (array_keys($a) as $index) {
                if (! array_key_exists($index, $b) || ! self::equals($a[$index], $b[$index])) {
                    return false;
                }
            }

            return true;
        }
        if ($a instanceof stdClass && $b instanceof stdClass) {
            $left = get_object_vars($a);
            $right = get_object_vars($b);
            if (count($left) !== count($right)) {
                return false;
            }
            /** @var mixed $value */
            foreach ($left as $name => $value) {
                if (! array_key_exists($name, $right) || ! self::equals($value, $right[$name])) {
                    return false;
                }
            }

            return true;
        }

        return $a === $b;
    }

    /** Whether `$value` is an integer in JSON's sense: `3` and `3.0`, not `3.5`. */
    public static function isInteger(mixed $value): bool
    {
        return is_int($value) || (is_float($value) && is_finite($value) && floor($value) === $value);
    }

    /** A schema constant (an `enum` value, a bound) as it would be written in JSON. */
    public static function encode(mixed $value): string
    {
        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);

        return $encoded === false ? '?' : $encoded;
    }

    /**
     * Turn a decoded instance into nested associative arrays — for code that reads
     * fields by name once validation has said what is there.
     */
    public static function toArrays(mixed $value): mixed
    {
        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        }
        if (is_array($value)) {
            return array_map(self::toArrays(...), $value);
        }

        return $value;
    }
}
