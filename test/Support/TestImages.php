<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

/**
 * Genuine images, made here so the tests need no binary fixture: a PNG of any size, in one colour.
 */
final class TestImages
{
    /** A valid PNG (ISO/IEC 15948): truecolour, eight bits a channel, every pixel this RGB colour. */
    public static function png(int $width = 64, int $height = 64, string $rgb = "\x0f\x76\x6e"): string
    {
        $rows = str_repeat("\x00" . str_repeat($rgb, $width), $height);

        return "\x89PNG\r\n\x1a\n"
            . self::chunk('IHDR', pack('NNCCCCC', $width, $height, 8, 2, 0, 0, 0))
            . self::chunk('IDAT', (string) gzcompress($rows))
            . self::chunk('IEND', '');
    }

    /** An SVG, which a logo must never be. */
    public static function svg(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><script>alert(1)</script></svg>';
    }

    private static function chunk(string $type, string $data): string
    {
        return pack('N', strlen($data)) . $type . $data . pack('N', crc32($type . $data));
    }
}
