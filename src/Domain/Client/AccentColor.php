<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Shared\InvalidValue;

/**
 * An application's accent colour on the sign-in pages: its buttons, links and chosen options
 * (`accent_color`). Six hexadecimal digits, as CSS writes them (`#0f766e`), kept in lower case; nothing
 * else, since the value is written into a stylesheet.
 *
 * The text drawn on it is worked out, not chosen: white or the pages' dark ink, whichever contrasts
 * more (WCAG 2.2, relative luminance and contrast ratio), so a pale brand colour never carries white text.
 */
final readonly class AccentColor
{
    public const string DARK_TEXT = '#12211a';
    public const string LIGHT_TEXT = '#ffffff';

    /** @param non-empty-string $hex */
    private function __construct(public string $hex)
    {
    }

    /** @throws InvalidValue For anything but `#` and six hexadecimal digits. */
    public static function fromString(string $value): self
    {
        if (preg_match('/^#[0-9A-Fa-f]{6}$/D', $value) !== 1) {
            throw new InvalidValue('An accent colour is # and six hexadecimal digits, such as #0f766e.');
        }

        /** @var non-empty-string $hex Seven characters, checked above. */
        $hex = strtolower($value);

        return new self($hex);
    }

    /** White or the dark ink, whichever reads better on this colour. */
    public function textColor(): string
    {
        $luminance = self::luminance($this->hex);
        $onWhite = 1.05 / ($luminance + 0.05);
        $onDark = ($luminance + 0.05) / (self::luminance(self::DARK_TEXT) + 0.05);

        return $onWhite >= $onDark ? self::LIGHT_TEXT : self::DARK_TEXT;
    }

    public function equals(self $other): bool
    {
        return $this->hex === $other->hex;
    }

    /** WCAG 2.2's relative luminance of an sRGB colour. */
    private static function luminance(string $hex): float
    {
        $channel = static function (string $pair): float {
            $value = (float) hexdec($pair) / 255.0;

            return $value <= 0.04045 ? $value / 12.92 : ((($value + 0.055) / 1.055) ** 2.4);
        };

        return 0.2126 * $channel(substr($hex, 1, 2))
            + 0.7152 * $channel(substr($hex, 3, 2))
            + 0.0722 * $channel(substr($hex, 5, 2));
    }
}
