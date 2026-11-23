<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Configuration;

use Clavia\Configuration\LocalFilePath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LocalFilePathTest extends TestCase
{
    public function testAnAbsolutePathIsLocal(): void
    {
        self::assertTrue(LocalFilePath::isAbsolute('/var/run/secrets/azure/tokens/azure-identity-token'));
    }

    #[DataProvider('notLocal')]
    public function testAnythingElseIsRefused(string $path): void
    {
        self::assertFalse(LocalFilePath::isAbsolute($path));
    }

    /** @return iterable<string, array{string}> */
    public static function notLocal(): iterable
    {
        yield 'a URL' => ['https://attacker.example/token'];
        yield 'a stream wrapper' => ['php://filter/resource=/etc/passwd'];
        yield 'a phar' => ['phar:///tmp/archive.phar/token'];
        yield 'a URL behind a slash' => ['/../http://attacker.example/token'];
        yield 'a relative path' => ['tokens/azure-identity-token'];
        yield 'a NUL' => ["/var/run/token\0.txt"];
        yield 'nothing' => [''];
    }
}
