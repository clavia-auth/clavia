<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

/**
 * The address a page names one of this server's static files by (`/auth/static/…`, served by Caddy), with
 * a version: the first twelve hexadecimal digits of the file's SHA-256 (`/auth/static/auth.css?v=…`).
 *
 * The pages' markup and these files change together at an upgrade. A browser that kept the old file under
 * the same address would pair new markup with an old stylesheet or module, and no header sent now reaches
 * a copy cached before it; a new address does. The file is read once per process and path.
 */
final class StaticAssets
{
    /** Where `/auth/static/…` lives: Caddy's root for it (`/app/public`). */
    private const string ROOT = __DIR__ . '/../../../../../public';

    /** @var array<string, string> What each path was answered with, once read. */
    private array $versioned = [];

    public function __construct(private readonly string $root = self::ROOT)
    {
    }

    /**
     * @param string $path A path under `/auth/static/`, as the page would name it.
     *
     * @return string The same path with its version; unchanged for anything else, or a file that is not
     *                there.
     */
    public function url(string $path): string
    {
        if (isset($this->versioned[$path])) {
            return $this->versioned[$path];
        }
        $file = $this->root . $path;
        $hash = str_starts_with($path, '/auth/static/') && ! str_contains($path, '..') && is_file($file)
            ? hash_file('sha256', $file)
            : false;

        return $this->versioned[$path] = $hash === false ? $path : $path . '?v=' . substr($hash, 0, 12);
    }
}
