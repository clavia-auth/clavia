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
    /**
     * @param array<array-key, mixed> $members A decoded JSON object. (PHP gives a member
     *                                         named like an integer an integer key.)
     */
    private function __construct(private array $members)
    {
    }

    /**
     * @param array<array-key, mixed> $members
     */
    public static function of(array $members): self
    {
        return new self($members);
    }

    public static function empty(): self
    {
        return new self([]);
    }

    /** Whether the member is present, even as `null`. */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->members);
    }

    public function string(string $name): ?string
    {
        /** @var mixed $value */
        $value = $this->members[$name] ?? null;

        return $value === null || is_string($value) ? $value : throw self::mistyped($name, 'a string');
    }

    public function bool(string $name): ?bool
    {
        /** @var mixed $value */
        $value = $this->members[$name] ?? null;

        return $value === null || is_bool($value) ? $value : throw self::mistyped($name, 'a boolean');
    }

    /**
     * @return list<string>|null
     */
    public function strings(string $name): ?array
    {
        /** @var mixed $value */
        $value = $this->members[$name] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw self::mistyped($name, 'an array');
        }

        $strings = [];
        /** @var mixed $item */
        foreach ($value as $item) {
            $strings[] = is_string($item) ? $item : throw self::mistyped($name, 'an array of strings');
        }

        return $strings;
    }

    /**
     * @return list<self>|null
     */
    public function objects(string $name): ?array
    {
        /** @var mixed $value */
        $value = $this->members[$name] ?? null;
        if ($value === null) {
            return null;
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw self::mistyped($name, 'an array');
        }

        $objects = [];
        /** @var mixed $item */
        foreach ($value as $item) {
            $objects[] = is_array($item) ? self::of($item) : throw self::mistyped($name, 'an array of objects');
        }

        return $objects;
    }

    private static function mistyped(string $name, string $expected): LogicException
    {
        return new LogicException(
            sprintf("The contract lets '%s' through as something other than %s.", $name, $expected),
        );
    }
}
