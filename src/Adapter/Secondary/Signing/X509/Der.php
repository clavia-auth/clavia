<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\X509;

use DateTimeImmutable;
use DateTimeZone;
use LogicException;

/**
 * The few DER encodings (ITU-T X.690 §8, §10) a certificate needs, each a tag, a definite length and
 * the content. Only what {@see SelfSignedCertificate} writes; nothing here parses.
 */
final readonly class Der
{
    private function __construct()
    {
    }

    /** @return non-empty-string */
    public static function sequence(string ...$parts): string
    {
        return self::tlv(0x30, implode('', $parts));
    }

    public static function set(string ...$parts): string
    {
        return self::tlv(0x31, implode('', $parts));
    }

    /** A non-negative INTEGER from unsigned big-endian bytes (§8.3: minimal, a 0x00 before a high bit). */
    public static function unsignedInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || ord($bytes[0]) > 0x7F) {
            $bytes = "\x00" . $bytes;
        }

        return self::tlv(0x02, $bytes);
    }

    public static function smallInteger(int $value): string
    {
        if ($value < 0 || $value > 127) {
            throw new LogicException('Only 0 to 127.');
        }

        return self::tlv(0x02, chr($value));
    }

    /** An OBJECT IDENTIFIER from its dotted form (§8.19). */
    public static function oid(string $dotted): string
    {
        $arcs = array_map('intval', explode('.', $dotted));
        $content = chr(40 * $arcs[0] + $arcs[1]);
        foreach (array_slice($arcs, 2) as $arc) {
            $chunk = chr($arc & 0x7F);
            for ($arc >>= 7; $arc > 0; $arc >>= 7) {
                $chunk = chr(0x80 | ($arc & 0x7F)) . $chunk;
            }
            $content .= $chunk;
        }

        return self::tlv(0x06, $content);
    }

    public static function null(): string
    {
        return "\x05\x00";
    }

    public static function boolean(bool $value): string
    {
        return self::tlv(0x01, $value ? "\xFF" : "\x00");
    }

    /** A BIT STRING whose last `$unusedBits` bits are padding (§8.6). */
    public static function bitString(string $bytes, int $unusedBits = 0): string
    {
        return self::tlv(0x03, chr($unusedBits) . $bytes);
    }

    public static function octetString(string $bytes): string
    {
        return self::tlv(0x04, $bytes);
    }

    public static function utf8String(string $text): string
    {
        return self::tlv(0x0C, $text);
    }

    /** RFC 5280 §4.1.2.5: UTCTime through 2049, GeneralizedTime from 2050, both in UTC to the second. */
    public static function time(DateTimeImmutable $instant): string
    {
        $utc = $instant->setTimezone(new DateTimeZone('UTC'));

        return (int) $utc->format('Y') < 2050
            ? self::tlv(0x17, $utc->format('ymdHis') . 'Z')
            : self::tlv(0x18, $utc->format('YmdHis') . 'Z');
    }

    /** `[n] EXPLICIT`, constructed, context-specific. */
    public static function explicit(int $tag, string $content): string
    {
        return self::tlv(0xA0 | $tag, $content);
    }

    /** @return non-empty-string */
    private static function tlv(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return chr($tag) . chr($length) . $content;
        }
        $bytes = ltrim(pack('N', $length), "\x00");

        return chr($tag) . chr(0x80 | strlen($bytes)) . $bytes . $content;
    }
}
