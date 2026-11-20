<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

/**
 * RFC 6901 JSON pointers, as used for locations in a document and in an instance.
 */
final class JsonPointer
{
    private function __construct()
    {
    }

    /** `$pointer` extended by one reference token, escaped (`~` → `~0`, `/` → `~1`). */
    public static function append(string $pointer, string|int $token): string
    {
        return $pointer . '/' . strtr((string) $token, ['~' => '~0', '/' => '~1']);
    }

    /**
     * The reference tokens of a pointer, unescaped.
     *
     * @return list<string>
     */
    public static function tokens(string $pointer): array
    {
        if ($pointer === '') {
            return [];
        }

        return array_map(
            static fn (string $token): string => strtr($token, ['~1' => '/', '~0' => '~']),
            array_slice(explode('/', $pointer), 1),
        );
    }
}
