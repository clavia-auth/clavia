<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Architecture;

use PHPUnit\Framework\TestCase;

/**
 * What `public/index.php` sets whatever php.ini says, before anything is emitted. The acceptance suite runs
 * the application in-process, so it never sees what PHP adds on the way out: this is where that is pinned.
 */
final class EntryPointTest extends TestCase
{
    /** RFC 9110 §8.3: no content, no Content-Type; PHP's default_mimetype would say text/html (#168). */
    public function testPhpLabelsNothingTheApplicationLeftUntyped(): void
    {
        self::assertSame(1, preg_match("/^ini_set\('default_mimetype', ''\);$/m", self::entryPoint()));
        self::assertLessThan(
            strpos(self::entryPoint(), '$app->run();'),
            strpos(self::entryPoint(), "ini_set('default_mimetype', '');"),
            'Set before the response goes out.',
        );
    }

    public function testErrorsAreNeverPrinted(): void
    {
        self::assertSame(1, preg_match("/^ini_set\('display_errors', '0'\);$/m", self::entryPoint()));
    }

    private static function entryPoint(): string
    {
        return (string) file_get_contents(SourceFiles::PROJECT_ROOT . '/public/index.php');
    }
}
