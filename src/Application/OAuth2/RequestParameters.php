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
     * The same parameters, with `$name` set to `$value` alone — in its place when it was
     * there, last when it was not — or removed, when null.
     */
    public function with(string $name, ?string $value): self
    {
        $values = $this->values;
        if ($value === null) {
            unset($values[$name]);
        } else {
            $values[$name] = [$value];
        }

        return new self($values);
    }

    /**
     * Rebuild parameters from {@see self::pairs()}.
     *
     * @param list<array{string, string}> $pairs
     */
    public static function fromPairs(array $pairs): self
    {
        $values = [];
        foreach ($pairs as [$name, $value]) {
            $values[$name][] = $value;
        }

        return new self($values);
    }

    /**
     * Every parameter as a name and a value, repetitions included, in order: to keep a request
     * as it was received, and rebuild it with {@see self::fromPairs()}.
     *
     * @return list<array{string, string}>
     */
    public function pairs(): array
    {
        $pairs = [];
        foreach ($this->values as $name => $values) {
            foreach ($values as $value) {
                $pairs[] = [(string) $name, $value];
            }
        }

        return $pairs;
    }

    /** The same parameters without `$name`. */
    public function without(string $name): self
    {
        return $this->with($name, null);
    }

    /**
     * Every parameter as a query string (RFC 3986 encoding), repetitions included, in the
     * order they were given — to send the browser back to the same request.
     */
    public function toQueryString(): string
    {
        $pairs = [];
        foreach ($this->values as $name => $values) {
            foreach ($values as $value) {
                $pairs[] = rawurlencode((string) $name) . '=' . rawurlencode($value);
            }
        }

        return implode('&', $pairs);
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
