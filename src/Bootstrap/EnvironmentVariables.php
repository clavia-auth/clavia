<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Configuration\Settings;
use Symfony\Component\Dotenv\Dotenv;

/**
 * Collects the `CLAVIA_*` variables the settings are built from.
 *
 * Precedence is the process environment, then the project's `.env` file. The file is
 * only parsed: nothing is exported into the process environment, so a variable some
 * other program reads at startup must be set in the shell or the container, not in
 * `.env`.
 */
final class EnvironmentVariables
{
    private function __construct()
    {
    }

    /**
     * @param string                     $projectRoot Directory that may hold a `.env` file.
     * @param array<string, string>|null $process     The process environment; `getenv()` when null.
     *
     * @return array<string, string>
     */
    public static function load(string $projectRoot, ?array $process = null): array
    {
        $file = $projectRoot . '/.env';

        /** @var array<string, string> $fromFile */
        $fromFile = is_file($file) && is_readable($file)
            ? new Dotenv()->parse((string) file_get_contents($file), $file)
            : [];

        // PHP turns a numeric variable name into an integer key, hence the is_string().
        /** @var array<array-key, string> $merged */
        $merged = array_merge($fromFile, $process ?? getenv());

        $variables = [];
        foreach ($merged as $name => $value) {
            if (is_string($name) && str_starts_with($name, Settings::VARIABLE_PREFIX)) {
                $variables[$name] = $value;
            }
        }

        return $variables;
    }
}
