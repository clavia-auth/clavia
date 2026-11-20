<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * Base64 with the URL- and filename-safe alphabet and no padding (RFC 4648 §5), as JOSE
 * uses it everywhere (RFC 7515 §2).
 */
final class Base64Url
{
    private function __construct()
    {
    }

    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Strict: padding, whitespace and the standard alphabet's `+` and `/` are refused,
     * so one value has exactly one encoding.
     *
     * @throws InvalidValue When the value is not unpadded base64url.
     */
    public static function decode(string $encoded): string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/D', $encoded) !== 1 || strlen($encoded) % 4 === 1) {
            throw new InvalidValue('Not unpadded base64url.');
        }

        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($decoded === false || self::encode($decoded) !== $encoded) {
            throw new InvalidValue('Not unpadded base64url.');
        }

        return $decoded;
    }
}
