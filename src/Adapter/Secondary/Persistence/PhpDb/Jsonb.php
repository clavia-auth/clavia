<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use JsonException;
use UnexpectedValueException;

/**
 * The two directions of a `jsonb` column: a PHP value written as a JSON text the SQL
 * casts (`CAST(:column AS jsonb)`), and the text PostgreSQL hands back decoded.
 */
final class Jsonb
{
    private function __construct()
    {
    }

    /**
     * @param array<array-key, mixed> $value
     *
     * @throws JsonException
     */
    public static function encode(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * A JSON array of strings, as every list column holds.
     *
     * @return list<string>
     *
     * @throws JsonException
     * @throws UnexpectedValueException When the column holds anything else.
     */
    public static function decodeStrings(string $json): array
    {
        $value = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($value) || ! array_is_list($value)) {
            throw new UnexpectedValueException('Expected a JSON array of strings.');
        }

        $strings = array_filter($value, is_string(...));
        if (count($strings) !== count($value)) {
            throw new UnexpectedValueException('Expected a JSON array of strings.');
        }

        return array_values($strings);
    }

    /**
     * A JSON object.
     *
     * @return array<string, mixed>
     *
     * @throws JsonException
     * @throws UnexpectedValueException When the column holds anything else.
     */
    public static function decodeObject(string $json): array
    {
        $value = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        if (! is_array($value) || ($value !== [] && array_is_list($value))) {
            throw new UnexpectedValueException('Expected a JSON object.');
        }

        /** @var array<string, mixed> */
        return $value;
    }
}
