<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\Schema\Schema;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Type;

/**
 * Turns the strings a parameter or header arrived as into the JSON value its schema
 * describes: `"2"` into `2` for an integer, `"a,b"` into `["a", "b"]` for an
 * unexploded array.
 *
 * Coercion is exact and never lenient: `"02"`, `"1e3"` and `" 1"` are not integers,
 * and `"yes"` is not a boolean. A string that does not coerce is passed on unchanged,
 * so the schema reports it ("Must be an integer.") with the same message as anywhere
 * else.
 */
final class ParameterDecoder
{
    private const string INTEGER = '/^-?(?:0|[1-9]\d*)$/D';
    private const string NUMBER = '/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/D';

    private function __construct()
    {
    }

    /**
     * @param list<string> $values  Every value sent: one, or several for an exploded array.
     * @param bool         $explode Whether an array arrives as repeated values rather than
     *                              one comma-separated value.
     *
     * @return mixed The value, or null when several values were sent for one that takes one.
     */
    public static function decode(Schema $schema, array $values, bool $explode): mixed
    {
        $schema = $schema->target();

        if ($schema->type === Type::Array) {
            $items = $explode ? $values : (count($values) === 1 ? explode(',', $values[0]) : null);
            if ($items === null) {
                return null;
            }
            $itemSchema = $schema->items?->target();

            return array_map(
                static fn (string $item): mixed => self::scalar($itemSchema?->type, $item),
                $items,
            );
        }

        return count($values) === 1 ? self::scalar($schema->type, $values[0]) : null;
    }

    private static function scalar(?Type $type, string $value): mixed
    {
        return match ($type) {
            Type::Integer => preg_match(self::INTEGER, $value) === 1 && self::fitsAnInt($value) ? (int) $value : $value,
            Type::Number => preg_match(self::NUMBER, $value) === 1
                ? (preg_match(self::INTEGER, $value) === 1 && self::fitsAnInt($value) ? (int) $value : (float) $value)
                : $value,
            Type::Boolean => match ($value) {
                'true' => true,
                'false' => false,
                default => $value,
            },
            default => $value,
        };
    }

    private static function fitsAnInt(string $digits): bool
    {
        return (string) (int) $digits === $digits;
    }
}
