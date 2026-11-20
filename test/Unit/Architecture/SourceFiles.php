<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Architecture;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Finds the project's own PHP files for the architecture tests.
 */
final class SourceFiles
{
    public const string PROJECT_ROOT = __DIR__ . '/../../..';

    private function __construct()
    {
    }

    /**
     * @param list<string> $directories Relative to the project root.
     *
     * @return list<string> Absolute paths of every `.php` file below them.
     */
    public static function in(array $directories): array
    {
        $files = [];

        foreach ($directories as $directory) {
            $path = self::PROJECT_ROOT . '/' . $directory;
            if (! is_dir($path)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
            );

            /** @var SplFileInfo $file */
            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $files[] = $file->getPathname();
                }
            }
        }

        sort($files);

        return $files;
    }

    /**
     * The fully-qualified names a file imports with `use` statements.
     *
     * @return list<string>
     */
    public static function imports(string $file): array
    {
        $imports = [];
        $tokens = token_get_all((string) file_get_contents($file));
        $count = count($tokens);
        $depth = 0;

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            if ($token === '{') {
                $depth++;
            } elseif ($token === '}') {
                $depth--;
            }

            // Inside a class body `use` imports a trait; inside a closure it captures a variable.
            if (! is_array($token) || $token[0] !== T_USE || $depth > 0) {
                continue;
            }

            for ($i++; $i < $count && $tokens[$i] !== ';' && $tokens[$i] !== '('; $i++) {
                $part = $tokens[$i];
                if (is_array($part) && in_array($part[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_STRING], true)) {
                    $imports[] = ltrim($part[1], '\\');
                }
            }
        }

        return array_values(array_diff($imports, ['function', 'const']));
    }
}
