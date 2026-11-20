<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use LogicException;
use stdClass;

/**
 * A request body that has already been checked against the Management API's contract,
 * read with the types the contract promised.
 *
 * Validation comes first ({@see ManagementApiMiddleware}), so a value of the wrong type
 * here is a contract that does not say what the handler assumes: a defect, reported as
 * a `LogicException` rather than as the caller's mistake.
 */
final readonly class JsonObject
{
    private function __construct(private stdClass $members)
    {
    }

    /** A decoded JSON object (`json_decode($json, false)`). */
    public static function of(stdClass $members): self
    {
        return new self($members);
    }

    public static function empty(): self
    {
        return new self(new stdClass());
    }

    /** Whether the member is present, even as `null`. */
    public function has(string $name): bool
    {
        return property_exists($this->members, $name);
    }

    public function string(string $name): ?string
    {
        /** @var mixed $value */
        $value = $this->value($name);

        return $value === null || is_string($value) ? $value : throw self::mistyped($name, 'a string');
    }

    public function bool(string $name): ?bool
    {
        /** @var mixed $value */
        $value = $this->value($name);

        return $value === null || is_bool($value) ? $value : throw self::mistyped($name, 'a boolean');
    }

    /**
     * @return list<string>|null
     */
    public function strings(string $name): ?array
    {
        $items = $this->list($name);
        if ($items === null) {
            return null;
        }

        $strings = [];
        /** @var mixed $item */
        foreach ($items as $item) {
            $strings[] = is_string($item) ? $item : throw self::mistyped($name, 'an array of strings');
        }

        return $strings;
    }

    /**
     * @return list<self>|null
     */
    public function objects(string $name): ?array
    {
        $items = $this->list($name);
        if ($items === null) {
            return null;
        }

        $objects = [];
        /** @var mixed $item */
        foreach ($items as $item) {
            $objects[] = $item instanceof stdClass
                ? new self($item)
                : throw self::mistyped($name, 'an array of objects');
        }

        return $objects;
    }

    private function value(string $name): mixed
    {
        return $this->has($name) ? $this->members->{$name} : null;
    }

    /**
     * @return list<mixed>|null
     */
    private function list(string $name): ?array
    {
        /** @var mixed $value */
        $value = $this->value($name);
        if ($value === null) {
            return null;
        }

        return is_array($value) && array_is_list($value) ? $value : throw self::mistyped($name, 'an array');
    }

    private static function mistyped(string $name, string $expected): LogicException
    {
        return new LogicException(
            sprintf("The contract lets '%s' through as something other than %s.", $name, $expected),
        );
    }
}
