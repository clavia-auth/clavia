<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Documentation;

use PHPUnit\Framework\TestCase;

/**
 * `docs/site/index.html`, the published Management API reference: what it loads, and from where.
 */
final class ApiReferencePageTest extends TestCase
{
    private const string PAGE = __DIR__ . '/../../../docs/site/index.html';

    public function testScalarIsPinnedToOneVersionFromJsDelivr(): void
    {
        preg_match_all('/<script[^>]*\bsrc="([^"]+)"/', self::page(), $scripts);

        // Every script the page loads, and only Scalar's: an exact version, so a release of
        // Scalar never changes a published page.
        self::assertCount(1, $scripts[1]);
        self::assertMatchesRegularExpression(
            '#^https://cdn\.jsdelivr\.net/npm/@scalar/api-reference@\d+\.\d+\.\d+/dist/browser/standalone\.js$#D',
            $scripts[1][0],
        );
    }

    public function testItRendersTheDocumentBesideItAndNamesTheRelease(): void
    {
        $page = self::page();

        self::assertStringContainsString("url: './management-api.yaml'", $page);
        self::assertStringContainsString('{{RELEASE}}', $page);
        self::assertStringContainsString('{{ROOT}}versions.json', $page);
    }

    public function testCodeSamplesNeverNameARealHost(): void
    {
        // The reader's own domain, through a server variable whose default is reserved (RFC 2606).
        self::assertStringContainsString("url: 'https://management.{domain}'", self::page());
        self::assertStringContainsString("default: 'example.com'", self::page());
    }

    private static function page(): string
    {
        $page = file_get_contents(self::PAGE);
        self::assertIsString($page);

        return $page;
    }
}
