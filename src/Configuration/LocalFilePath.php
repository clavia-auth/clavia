<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

/**
 * What a setting naming a file on this host must be: an absolute path, without a scheme or a NUL.
 *
 * PHP's file functions take URLs too (`http://`, `php://`, `phar://`): a path that is a URL makes
 * a read a network request, or worse. Refused when the settings are read, and checked again where
 * the file is opened.
 */
final class LocalFilePath
{
    private function __construct()
    {
    }

    public static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/')
            && ! str_contains($path, "\0")
            && ! str_contains($path, '://');
    }
}
