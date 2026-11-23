<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Management;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * `docs/openapi/management-api.yaml`, read as the documentation it also is: a rendered reference
 * (Scalar, Redoc) builds its navigation from each operation's `summary` and each tag's
 * `x-displayName`, so those stay short labels, and the detail lives in `description`.
 */
final class ManagementDocumentationTest extends TestCase
{
    /** A label is a verb and its object: a handful of words fits a sidebar. */
    private const int MAX_SUMMARY_WORDS = 6;
    private const int MAX_SUMMARY_LENGTH = 40;

    /** Words in lower case after the first, but for an acronym (`API`, `MFA`), plural or not. */
    private const string LABEL = "/^[A-Z][a-z]*(?: (?:[a-z'’]+|[A-Z]{2,}s?))*$/D";

    /** @var array<array-key, mixed>|null */
    private static ?array $document = null;

    public function testEverySummaryIsAShortLabel(): void
    {
        foreach (self::operations() as $name => $operation) {
            $summary = $operation['summary'] ?? null;
            self::assertIsString($summary, $name . ' has no summary.');
            self::assertLessThanOrEqual(self::MAX_SUMMARY_LENGTH, strlen($summary), $name . ': ' . $summary);
            self::assertLessThanOrEqual(self::MAX_SUMMARY_WORDS, str_word_count($summary), $name . ': ' . $summary);
            // Sentence case, no full stop: a capital only to start, or in an acronym (API, MFA).
            self::assertMatchesRegularExpression(self::LABEL, $summary, $name);
        }
    }

    public function testEveryTagIsNamedForTheNavigationAndUsed(): void
    {
        $tags = self::document()['tags'] ?? null;
        self::assertIsArray($tags);
        $declared = [];
        foreach ($tags as $tag) {
            self::assertIsArray($tag);
            self::assertIsString($tag['name']);
            self::assertIsString($tag['x-displayName'] ?? null, $tag['name'] . ' has no x-displayName.');
            self::assertIsString($tag['description'] ?? null, $tag['name'] . ' has no description.');
            $declared[] = $tag['name'];
        }

        $used = [];
        foreach (self::operations() as $name => $operation) {
            $operationTags = $operation['tags'] ?? null;
            self::assertIsArray($operationTags, $name);
            self::assertCount(1, $operationTags, $name . ' belongs in one place of the navigation.');
            /** @var mixed $tag */
            $tag = $operationTags[0] ?? null;
            self::assertIsString($tag, $name);
            $used[] = $tag;
        }
        self::assertSame([], array_values(array_diff($used, $declared)), 'Operations use tags nobody declared.');
        self::assertSame([], array_values(array_diff($declared, $used)), 'Tags no operation uses.');
    }

    /** @return array<string, array<array-key, mixed>> Operations by `METHOD path`. */
    private static function operations(): array
    {
        $paths = self::document()['paths'] ?? null;
        self::assertIsArray($paths);
        $operations = [];
        foreach ($paths as $path => $item) {
            self::assertIsArray($item);
            foreach (['get', 'post', 'put', 'patch', 'delete'] as $method) {
                if (isset($item[$method]) && is_array($item[$method])) {
                    $operations[strtoupper($method) . ' ' . (string) $path] = $item[$method];
                }
            }
        }
        self::assertNotEmpty($operations);

        return $operations;
    }

    /** @return array<array-key, mixed> */
    private static function document(): array
    {
        if (self::$document === null) {
            /** @var mixed $parsed */
            $parsed = Yaml::parseFile(__DIR__ . '/../../../../../../docs/openapi/management-api.yaml');
            self::assertIsArray($parsed);
            self::$document = $parsed;
        }

        return self::$document;
    }
}
