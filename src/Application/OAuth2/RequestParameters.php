<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2;

/**
 * The parameters of an OAuth 2.0 request, with every value seen for each name.
 *
 * RFC 6749 §3.1 and §3.2: request parameters must not be included more than once. A
 * flat map would hide a repetition — and which of two `redirect_uri` or two
 * `code_challenge` values a server honours is exactly the kind of ambiguity an attack
 * is built on. So repetitions are kept, and the use cases refuse them.
 */
final readonly class RequestParameters
{
    /**
     * @param array<array-key, list<string>> $values Parameter name to every value it was given, in
     *                                               order. (PHP turns an all-digit name into an
     *                                               integer key; lookups work either way.)
     */
    public function __construct(private array $values)
    {
    }

    /**
     * @param array<string, string> $map
     */
    public static function fromMap(array $map): self
    {
        return new self(array_map(static fn (string $value): array => [$value], $map));
    }

    /**
     * The value of a parameter given exactly once and not empty; null when it is absent
     * or empty (RFC 6749 §3.1: a parameter sent without a value is treated as omitted).
     */
    public function get(string $name): ?string
    {
        $value = $this->values[$name][0] ?? '';

        return $value === '' ? null : $value;
    }

    public function isRepeated(string $name): bool
    {
        return count($this->values[$name] ?? []) > 1;
    }

    /**
     * The names given more than once.
     *
     * @return list<string>
     */
    public function repeated(): array
    {
        $repeated = array_filter($this->values, static fn (array $values): bool => count($values) > 1);

        return array_map(strval(...), array_keys($repeated));
    }
}
