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
 * Every PHP file opens with the header kept in `.docheader`.
 */
final class LicenseHeaderTest extends TestCase
{
    public function testEveryPhpFileCarriesTheLicenseHeader(): void
    {
        $header = rtrim((string) file_get_contents(SourceFiles::PROJECT_ROOT . '/.docheader'));
        $files = SourceFiles::in(['bin', 'config', 'public', 'src', 'test']);
        $files[] = SourceFiles::PROJECT_ROOT . '/bin/clavia';

        $missing = array_values(array_filter(
            $files,
            static fn (string $file): bool => ! str_contains(
                (string) file_get_contents($file),
                "<?php\n\n" . $header . "\n",
            ),
        ));

        self::assertNotEmpty($files);
        self::assertSame([], $missing);
    }
}
