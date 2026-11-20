<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Schema;

use Uri\Rfc3986\Uri;

/**
 * The `format` values this validator checks. OpenAPI leaves `format` open (§4.4), so
 * a format not listed here constrains nothing — it is an annotation — and a format is
 * only checked on the type it belongs to: `int32` on integers, `uuid` on strings.
 */
final class Formats
{
    private const string DATE = '(\d{4})-(\d{2})-(\d{2})';
    private const string UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/Di';
    private const string BASE64 = '/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/D';
    private const string TIME = '([01]\d|2[0-3]):([0-5]\d):([0-5]\d|60)(\.\d+)?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)';

    private function __construct()
    {
    }

    /** Whether `$value` satisfies `$format` — true for a format this class does not know. */
    public static function accepts(string $format, mixed $value): bool
    {
        if (is_string($value)) {
            return match ($format) {
                'date-time' => self::dateTime($value),
                'date' => self::date($value),
                'uuid' => preg_match(self::UUID, $value) === 1,
                'email' => filter_var($value, FILTER_VALIDATE_EMAIL, FILTER_FLAG_EMAIL_UNICODE) !== false,
                'uri' => Uri::parse($value)?->getScheme() !== null,
                'uri-reference' => Uri::parse($value) !== null,
                'ipv4' => filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false,
                'ipv6' => filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false,
                'hostname' => filter_var($value, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false,
                'byte' => preg_match(self::BASE64, $value) === 1,
                default => true,
            };
        }

        if (JsonValue::isInteger($value)) {
            /** @var int|float $value */
            return match ($format) {
                'int32' => $value >= -2147483648 && $value <= 2147483647,
                'int64' => is_int($value),
                default => true,
            };
        }

        return true;
    }

    /** RFC 3339 §5.6 `date-time`, with a real calendar date. */
    private static function dateTime(string $value): bool
    {
        return preg_match('/^' . self::DATE . '[Tt]' . self::TIME . '$/D', $value, $parts) === 1
            && checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]);
    }

    /** RFC 3339 §5.6 `full-date`. */
    private static function date(string $value): bool
    {
        return preg_match('/^' . self::DATE . '$/D', $value, $parts) === 1
            && checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1]);
    }
}
