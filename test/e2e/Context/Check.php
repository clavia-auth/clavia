<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use RuntimeException;

/**
 * What the scenarios assert with. PHPUnit's `Assert` is not used: its failure path reads PHPUnit's own
 * configuration, which does not exist under Behat, so a failed check ended in a fatal error that hid
 * the check. These throw, and Behat prints the message.
 */
final class Check
{
    public static function that(bool $condition, string $message = ''): void
    {
        if (! $condition) {
            throw new RuntimeException($message === '' ? 'Failed asserting that a condition is true.' : $message);
        }
    }

    public static function same(mixed $expected, mixed $actual, string $message = ''): void
    {
        self::that($expected === $actual, sprintf(
            '%s (expected %s, got %s)',
            $message === '' ? 'Not the same' : $message,
            self::show($expected),
            self::show($actual),
        ));
    }

    public static function notSame(mixed $unexpected, mixed $actual, string $message = ''): void
    {
        self::that($unexpected !== $actual, ($message === '' ? 'Unexpectedly the same' : $message)
            . ': ' . self::show($actual));
    }

    /** @param array<array-key, mixed> $haystack */
    public static function contains(mixed $needle, array $haystack, string $message = ''): void
    {
        self::that(in_array($needle, $haystack, true), sprintf(
            '%s (%s is not in %s)',
            $message === '' ? 'Missing' : $message,
            self::show($needle),
            self::show($haystack),
        ));
    }

    public static function startsWith(string $prefix, string $actual, string $message = ''): void
    {
        self::that(str_starts_with($actual, $prefix), sprintf(
            '%s (%s does not start with %s)',
            $message === '' ? 'Wrong start' : $message,
            self::show($actual),
            self::show($prefix),
        ));
    }

    public static function includes(string $needle, string $actual, string $message = ''): void
    {
        self::that(str_contains($actual, $needle), sprintf(
            '%s (%s does not contain %s)',
            $message === '' ? 'Missing' : $message,
            self::show($actual),
            self::show($needle),
        ));
    }

    /** @param non-empty-string $pattern */
    public static function matches(string $pattern, string $actual, string $message = ''): void
    {
        self::that(preg_match($pattern, $actual) === 1, sprintf(
            '%s (%s does not match %s)',
            $message === '' ? 'No match' : $message,
            self::show($actual),
            $pattern,
        ));
    }

    /** @psalm-assert string $value */
    public static function string(mixed $value, string $message = ''): void
    {
        self::that(is_string($value), ($message === '' ? 'Not a string' : $message) . ': ' . self::show($value));
    }

    public static function show(mixed $value): string
    {
        $text = is_string($value) ? '"' . $value . '"' : json_encode($value, JSON_UNESCAPED_SLASHES);

        return mb_strimwidth($text === false ? get_debug_type($value) : $text, 0, 400, '…');
    }
}
