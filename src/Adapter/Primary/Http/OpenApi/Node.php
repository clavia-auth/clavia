<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use stdClass;

/**
 * A value of the OpenAPI document as parsed — an object (`stdClass`), a list, or a
 * scalar — together with where it sits, so every complaint about it can say so.
 *
 * The accessors check the shape the specification requires and throw
 * {@see InvalidDocument} otherwise; nothing downstream sees an unchecked value.
 */
final readonly class Node
{
    private function __construct(
        public mixed $value,
        /** An RFC 6901 pointer from the document root; `''` is the root. */
        public string $pointer,
        /**
         * The member name this node was reached by, as written — kept here rather than
         * as an array key, where PHP would turn `'200'` into `200`.
         */
        public string $name = '',
    ) {
    }

    public static function root(mixed $value): self
    {
        return new self($value, '');
    }

    public function isObject(): bool
    {
        return $this->value instanceof stdClass;
    }

    /**
     * The members of an object, in document order; each knows its {@see self::$name}.
     *
     * @return list<self>
     *
     * @throws InvalidDocument When the value is not an object.
     */
    public function members(): array
    {
        $object = $this->value instanceof stdClass ? $this->value : throw $this->invalid('must be an object');

        $members = [];
        /** @var mixed $value */
        foreach (get_object_vars($object) as $name => $value) {
            $name = (string) $name;
            $members[] = new self($value, JsonPointer::append($this->pointer, $name), $name);
        }

        return $members;
    }

    /**
     * The names of an object's members, in document order.
     *
     * @return list<string>
     *
     * @throws InvalidDocument When the value is not an object.
     */
    public function names(): array
    {
        return array_map(static fn (self $member): string => $member->name, $this->members());
    }

    /**
     * @return list<self>
     *
     * @throws InvalidDocument When the value is not a list.
     */
    public function items(): array
    {
        if (! is_array($this->value) || ! array_is_list($this->value)) {
            throw $this->invalid('must be a list');
        }

        $items = [];
        /** @var mixed $value */
        foreach ($this->value as $index => $value) {
            $items[] = new self($value, JsonPointer::append($this->pointer, $index));
        }

        return $items;
    }

    public function has(string $name): bool
    {
        return $this->value instanceof stdClass && property_exists($this->value, $name);
    }

    /**
     * @throws InvalidDocument When the value is not an object or lacks the member.
     */
    public function member(string $name): self
    {
        return $this->optional($name) ?? throw $this->invalid(sprintf("must have '%s'", $name));
    }

    /**
     * @throws InvalidDocument When the value is not an object.
     */
    public function optional(string $name): ?self
    {
        $object = $this->value instanceof stdClass ? $this->value : throw $this->invalid('must be an object');

        return property_exists($object, $name)
            ? new self($object->{$name}, JsonPointer::append($this->pointer, $name), $name)
            : null;
    }

    /**
     * Refuse members this validator does not know: a misspelt keyword silently ignored
     * would be a constraint silently dropped. `x-` extensions are always allowed.
     *
     * @param list<string> $known
     *
     * @throws InvalidDocument
     */
    public function allowOnly(array $known): void
    {
        foreach ($this->names() as $name) {
            if (! in_array($name, $known, true) && ! str_starts_with($name, 'x-')) {
                throw InvalidDocument::at(JsonPointer::append($this->pointer, $name), 'is not supported here');
            }
        }
    }

    /** @throws InvalidDocument */
    public function string(): string
    {
        return is_string($this->value) ? $this->value : throw $this->invalid('must be a string');
    }

    /** @throws InvalidDocument */
    public function bool(): bool
    {
        return is_bool($this->value) ? $this->value : throw $this->invalid('must be a boolean');
    }

    /**
     * @return non-negative-int
     *
     * @throws InvalidDocument
     */
    public function count(): int
    {
        return is_int($this->value) && $this->value >= 0
            ? $this->value
            : throw $this->invalid('must be a non-negative integer');
    }

    /** @throws InvalidDocument */
    public function number(): int|float
    {
        return is_int($this->value) || is_float($this->value)
            ? $this->value
            : throw $this->invalid('must be a number');
    }

    /** @throws InvalidDocument */
    public function stringMember(string $name, ?string $default = null): ?string
    {
        return $this->optional($name)?->string() ?? $default;
    }

    /** @throws InvalidDocument */
    public function boolMember(string $name, bool $default): bool
    {
        return $this->optional($name)?->bool() ?? $default;
    }

    public function invalid(string $problem): InvalidDocument
    {
        return InvalidDocument::at($this->pointer, $problem);
    }
}
