<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

use Clavia\Adapter\Primary\Http\OpenApi\JsonPointer;
use stdClass;

/**
 * Validates a JSON instance against a compiled {@see Schema}, collecting every
 * violation rather than stopping at the first: a caller fixes a request in one go.
 *
 * Semantics are OpenAPI 3.0's Schema Object (a subset of JSON Schema draft 4–5): `null`
 * is valid only where `nullable` (or when no `type` is given), `exclusiveMinimum` is a
 * flag on `minimum`, and `readOnly` / `writeOnly` depend on the {@see Direction}.
 * Lengths count code points. Keywords apply to the type they concern and are ignored
 * on others (`minLength` says nothing about a number), as JSON Schema specifies.
 *
 * Messages state the constraint and never the value: see {@see SchemaViolation}.
 */
final class SchemaValidator
{
    private function __construct()
    {
    }

    /**
     * @return list<SchemaViolation> Empty when the instance is valid.
     */
    public static function validate(mixed $instance, Schema $schema, Direction $direction): array
    {
        $violations = [];
        self::check($instance, $schema->target(), $direction, '', $violations);

        return $violations;
    }

    /** Whether the instance is valid — for `anyOf`, `oneOf` and `not`, which only count. */
    public static function isValid(mixed $instance, Schema $schema, Direction $direction): bool
    {
        return self::validate($instance, $schema, $direction) === [];
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function check(
        mixed $instance,
        Schema $schema,
        Direction $direction,
        string $pointer,
        array &$violations,
    ): void {
        if ($instance === null) {
            self::checkNull($schema, $pointer, $violations);
            self::checkComposition($instance, $schema, $direction, $pointer, $violations);

            return;
        }

        if ($schema->type !== null && ! self::hasType($instance, $schema->type)) {
            $violations[] = new SchemaViolation($pointer, sprintf('Must be %s.', $schema->type->described()));

            return;
        }

        if ($schema->enum !== null && ! self::inEnum($instance, $schema->enum)) {
            $violations[] = new SchemaViolation($pointer, self::enumMessage($schema->enum));
        }

        if ($schema->format !== null && ! Formats::accepts($schema->format, $instance)) {
            $violations[] = new SchemaViolation($pointer, sprintf('Must be a valid %s.', $schema->format));
        }

        if (is_string($instance)) {
            self::checkString($instance, $schema, $pointer, $violations);
        } elseif (is_int($instance) || is_float($instance)) {
            self::checkNumber($instance, $schema, $pointer, $violations);
        } elseif (is_array($instance) && array_is_list($instance)) {
            self::checkArray($instance, $schema, $direction, $pointer, $violations);
        } elseif ($instance instanceof stdClass) {
            self::checkObject($instance, $schema, $direction, $pointer, $violations);
        }

        self::checkComposition($instance, $schema, $direction, $pointer, $violations);
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function checkNull(Schema $schema, string $pointer, array &$violations): void
    {
        if ($schema->nullable) {
            return;
        }
        if ($schema->type !== null) {
            $violations[] = new SchemaViolation($pointer, sprintf('Must be %s, not null.', $schema->type->described()));

            return;
        }
        if ($schema->enum !== null && ! self::inEnum(null, $schema->enum)) {
            $violations[] = new SchemaViolation($pointer, self::enumMessage($schema->enum));
        }
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function checkString(string $instance, Schema $schema, string $pointer, array &$violations): void
    {
        $length = mb_strlen($instance, 'UTF-8');
        if ($schema->minLength !== null && $length < $schema->minLength) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must be at least %s long.', self::count($schema->minLength, 'character')),
            );
        }
        if ($schema->maxLength !== null && $length > $schema->maxLength) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must be at most %s long.', self::count($schema->maxLength, 'character')),
            );
        }
        if ($schema->pattern !== null && preg_match($schema->pattern, $instance) !== 1) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must match the pattern %s.', (string) $schema->source),
            );
        }
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function checkNumber(int|float $instance, Schema $schema, string $pointer, array &$violations): void
    {
        if ($schema->minimum !== null) {
            $below = $schema->exclusiveMinimum ? $instance <= $schema->minimum : $instance < $schema->minimum;
            if ($below) {
                $violations[] = new SchemaViolation($pointer, sprintf(
                    'Must be greater than %s%s.',
                    $schema->exclusiveMinimum ? '' : 'or equal to ',
                    JsonValue::encode($schema->minimum),
                ));
            }
        }
        if ($schema->maximum !== null) {
            $above = $schema->exclusiveMaximum ? $instance >= $schema->maximum : $instance > $schema->maximum;
            if ($above) {
                $violations[] = new SchemaViolation($pointer, sprintf(
                    'Must be less than %s%s.',
                    $schema->exclusiveMaximum ? '' : 'or equal to ',
                    JsonValue::encode($schema->maximum),
                ));
            }
        }
        if ($schema->multipleOf !== null && ! self::isMultiple($instance, $schema->multipleOf)) {
            $violations[] = new SchemaViolation($pointer, sprintf(
                'Must be a multiple of %s.',
                JsonValue::encode($schema->multipleOf),
            ));
        }
    }

    /**
     * @param list<mixed>           $instance
     * @param list<SchemaViolation> $violations
     */
    private static function checkArray(
        array $instance,
        Schema $schema,
        Direction $direction,
        string $pointer,
        array &$violations,
    ): void {
        $count = count($instance);
        if ($schema->minItems !== null && $count < $schema->minItems) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must hold at least %s.', self::count($schema->minItems, 'item')),
            );
        }
        if ($schema->maxItems !== null && $count > $schema->maxItems) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must hold at most %s.', self::count($schema->maxItems, 'item')),
            );
        }
        if ($schema->uniqueItems && ! self::allDistinct($instance)) {
            $violations[] = new SchemaViolation($pointer, 'Must not hold the same item twice.');
        }

        if ($schema->items !== null) {
            $items = $schema->items->target();
            /** @var mixed $item */
            foreach ($instance as $index => $item) {
                self::check($item, $items, $direction, JsonPointer::append($pointer, $index), $violations);
            }
        }
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function checkObject(
        stdClass $instance,
        Schema $schema,
        Direction $direction,
        string $pointer,
        array &$violations,
    ): void {
        /** @var array<string, mixed> $members */
        $members = get_object_vars($instance);

        $count = count($members);
        if ($schema->minProperties !== null && $count < $schema->minProperties) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must hold at least %s.', self::count($schema->minProperties, 'member')),
            );
        }
        if ($schema->maxProperties !== null && $count > $schema->maxProperties) {
            $violations[] = new SchemaViolation(
                $pointer,
                sprintf('Must hold at most %s.', self::count($schema->maxProperties, 'member')),
            );
        }

        foreach ($schema->required as $name) {
            if (array_key_exists($name, $members)) {
                continue;
            }
            $property = isset($schema->properties[$name]) ? $schema->properties[$name]->target() : null;
            // A property that does not travel this way cannot be required to (§4.7.24).
            if (
                ($direction === Direction::Request && $property?->readOnly === true)
                || ($direction === Direction::Response && $property?->writeOnly === true)
            ) {
                continue;
            }
            $violations[] = new SchemaViolation(JsonPointer::append($pointer, $name), 'Is required.');
        }

        /** @var mixed $value */
        foreach ($members as $name => $value) {
            $at = JsonPointer::append($pointer, $name);
            if (isset($schema->properties[$name])) {
                $property = $schema->properties[$name]->target();
                if ($direction === Direction::Request && $property->readOnly) {
                    $violations[] = new SchemaViolation($at, 'Is read-only: it cannot be sent.');
                    continue;
                }
                if ($direction === Direction::Response && $property->writeOnly) {
                    $violations[] = new SchemaViolation($at, 'Is write-only: it must never be returned.');
                    continue;
                }
                self::check($value, $property, $direction, $at, $violations);
            } elseif ($schema->additionalProperties === false) {
                $violations[] = new SchemaViolation($at, 'Is not allowed.');
            } elseif ($schema->additionalProperties instanceof Schema) {
                self::check($value, $schema->additionalProperties->target(), $direction, $at, $violations);
            }
        }
    }

    /**
     * @param list<SchemaViolation> $violations
     */
    private static function checkComposition(
        mixed $instance,
        Schema $schema,
        Direction $direction,
        string $pointer,
        array &$violations,
    ): void {
        foreach ($schema->allOf as $part) {
            self::check($instance, $part->target(), $direction, $pointer, $violations);
        }

        if ($schema->anyOf !== []) {
            $matching = self::countMatching($instance, $schema->anyOf, $direction);
            if ($matching === 0) {
                $violations[] = new SchemaViolation($pointer, 'Must match at least one of the allowed shapes.');
            }
        }

        if ($schema->oneOf !== []) {
            $matching = self::countMatching($instance, $schema->oneOf, $direction);
            if ($matching !== 1) {
                $violations[] = new SchemaViolation($pointer, sprintf(
                    'Must match exactly one of the allowed shapes; it matches %d.',
                    $matching,
                ));
            }
        }

        if ($schema->not !== null && self::isValid($instance, $schema->not, $direction)) {
            $violations[] = new SchemaViolation($pointer, 'Must not match the excluded shape.');
        }
    }

    /**
     * @param list<Schema> $schemas
     */
    private static function countMatching(mixed $instance, array $schemas, Direction $direction): int
    {
        return count(array_filter(
            $schemas,
            static fn (Schema $schema): bool => self::isValid($instance, $schema, $direction),
        ));
    }

    private static function hasType(mixed $instance, Type $type): bool
    {
        return match ($type) {
            Type::String => is_string($instance),
            Type::Integer => JsonValue::isInteger($instance),
            Type::Number => is_int($instance) || (is_float($instance) && is_finite($instance)),
            Type::Boolean => is_bool($instance),
            Type::Array => is_array($instance) && array_is_list($instance),
            Type::Object => $instance instanceof stdClass,
        };
    }

    /**
     * @param list<mixed> $enum
     */
    private static function inEnum(mixed $instance, array $enum): bool
    {
        return array_any($enum, static fn (mixed $allowed): bool => JsonValue::equals($instance, $allowed));
    }

    /**
     * @param list<mixed> $enum
     */
    private static function enumMessage(array $enum): string
    {
        $shown = array_map(JsonValue::encode(...), array_slice($enum, 0, 10));

        return sprintf('Must be one of %s%s.', implode(', ', $shown), count($enum) > 10 ? ', …' : '');
    }

    /**
     * @param list<mixed> $items
     */
    private static function allDistinct(array $items): bool
    {
        $count = count($items);
        for ($i = 0; $i < $count; ++$i) {
            for ($j = $i + 1; $j < $count; ++$j) {
                if (JsonValue::equals($items[$i], $items[$j])) {
                    return false;
                }
            }
        }

        return true;
    }

    /** `1 item`, `8 characters`. */
    private static function count(int $count, string $noun): string
    {
        return $count . ' ' . $noun . ($count === 1 ? '' : 's');
    }

    private static function isMultiple(int|float $instance, int|float $divisor): bool
    {
        if (is_int($instance) && is_int($divisor)) {
            return $instance % $divisor === 0;
        }

        $quotient = (float) $instance / (float) $divisor;

        // Decimal divisors (0.01) are not exact in binary; accept a quotient within a
        // relative epsilon of an integer.
        return abs($quotient - round($quotient)) <= 1e-9 * max(1.0, abs($quotient));
    }
}
