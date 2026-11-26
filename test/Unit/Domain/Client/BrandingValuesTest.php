<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Client;

use Clavia\Domain\Client\AccentColor;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\TestImages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An application's accent colour and logo (#25): only what is safe to put in a stylesheet and an img. */
final class BrandingValuesTest extends TestCase
{
    public function testAColourIsKeptInLowerCase(): void
    {
        self::assertSame('#0f766e', AccentColor::fromString('#0F766E')->hex);
    }

    #[DataProvider('notColours')]
    public function testAnythingElseIsNoColour(string $value): void
    {
        $this->expectException(InvalidValue::class);

        AccentColor::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notColours(): iterable
    {
        yield 'no hash' => ['0f766e'];
        yield 'three digits' => ['#0f7'];
        yield 'a name' => ['red'];
        yield 'a way out of the stylesheet' => ['#0f766e;}body{'];
        yield 'a trailing newline' => ["#0f766e\n"];
    }

    /** WCAG 2.2 contrast: the text on a colour is whichever of white and dark ink reads better. */
    public function testTheTextOnAColourIsWorkedOut(): void
    {
        self::assertSame(AccentColor::LIGHT_TEXT, AccentColor::fromString('#2d6a4f')->textColor());
        self::assertSame(AccentColor::LIGHT_TEXT, AccentColor::fromString('#000000')->textColor());
        self::assertSame(AccentColor::DARK_TEXT, AccentColor::fromString('#f9e27d')->textColor());
        self::assertSame(AccentColor::DARK_TEXT, AccentColor::fromString('#ffffff')->textColor());
    }

    public function testALogoIsRecognisedByItsContent(): void
    {
        $logo = ClientLogo::fromBytes(ClientId::fromString('app'), TestImages::png(64, 32));

        self::assertSame('image/png', $logo->mediaType);
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/D', $logo->version);
        self::assertNotSame(
            $logo->version,
            ClientLogo::fromBytes(ClientId::fromString('app'), TestImages::png(64, 33))->version,
            'Another image, another version.',
        );
    }

    #[DataProvider('notLogos')]
    public function testAnythingElseIsNoLogo(string $bytes): void
    {
        $this->expectException(InvalidValue::class);

        ClientLogo::fromBytes(ClientId::fromString('app'), $bytes);
    }

    /** @return iterable<string, array{string}> */
    public static function notLogos(): iterable
    {
        yield 'nothing' => [''];
        yield 'an SVG, which can carry script' => [TestImages::svg()];
        yield 'text' => ['GIF89a but not really'];
        yield 'a GIF' => [base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')];
        yield 'smaller than 16 pixels' => [TestImages::png(15, 64)];
        yield 'larger than 1024 pixels' => [TestImages::png(64, 1025)];
        yield 'heavier than 256 KiB' => [TestImages::png() . str_repeat("\0", ClientLogo::MAX_BYTES)];
    }
}
