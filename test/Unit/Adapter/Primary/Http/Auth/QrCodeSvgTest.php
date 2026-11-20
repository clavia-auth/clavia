<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Auth\QrCodeSvg;
use DOMDocument;
use PHPUnit\Framework\TestCase;

/**
 * The QR code is printed into a page whose policy allows no inline style, so it must
 * carry none, and it takes its colour from the theme.
 */
final class QrCodeSvgTest extends TestCase
{
    private const string URI = 'otpauth://totp/Clavia%3Aada%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    public function testTheSvgIsWellFormedAndTakesItsColourFromTheText(): void
    {
        $svg = QrCodeSvg::of(self::URI);

        $document = new DOMDocument();
        self::assertTrue($svg !== '' && $document->loadXML($svg));
        $root = $document->documentElement;
        self::assertNotNull($root);
        self::assertSame('svg', $root->localName);
        self::assertSame('currentColor', $root->getAttribute('fill'));
        self::assertSame('img', $root->getAttribute('role'));
        self::assertNotSame('', $root->getAttribute('aria-label'));
        self::assertGreaterThan(0, $root->getElementsByTagName('path')->length);
    }

    public function testItCarriesNoStyleNoBackgroundAndNoScript(): void
    {
        $svg = QrCodeSvg::of(self::URI);

        self::assertStringNotContainsString('style', $svg);
        self::assertStringNotContainsString('<rect', $svg);
        self::assertStringNotContainsString('<script', $svg);
        self::assertStringNotContainsString('<?xml', $svg);
        self::assertSame(1, substr_count($svg, 'fill='));
    }

    public function testTheSeedIsNotWrittenIntoTheMarkup(): void
    {
        self::assertStringNotContainsString('JBSWY3DP', QrCodeSvg::of(self::URI));
    }

    public function testADifferentUriDrawsADifferentCode(): void
    {
        self::assertNotSame(QrCodeSvg::of(self::URI), QrCodeSvg::of(self::URI . 'A'));
        self::assertSame(QrCodeSvg::of(self::URI), QrCodeSvg::of(self::URI));
    }
}
