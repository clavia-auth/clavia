<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Shared;

use Clavia\Adapter\Primary\Http\Shared\StaticAssets;
use PHPUnit\Framework\TestCase;

/** A static file's address changes with its content, so no browser pairs new markup with an old file. */
final class StaticAssetsTest extends TestCase
{
    public function testTheShippedFilesAreVersionedByTheirContent(): void
    {
        $assets = new StaticAssets();
        $file = dirname(__DIR__, 6) . '/public/auth/static/auth.css';

        self::assertSame(
            '/auth/static/auth.css?v=' . substr((string) hash_file('sha256', $file), 0, 12),
            $assets->url('/auth/static/auth.css'),
        );
        self::assertMatchesRegularExpression(
            '#^/auth/static/passkeys\.js\?v=[0-9a-f]{12}$#D',
            $assets->url('/auth/static/passkeys.js'),
        );
    }

    public function testAnythingElseIsLeftAsItIs(): void
    {
        $assets = new StaticAssets();

        self::assertSame('/auth/static/missing.css', $assets->url('/auth/static/missing.css'));
        self::assertSame('/auth/static/../index.php', $assets->url('/auth/static/../index.php'));
        self::assertSame('/index.php', $assets->url('/index.php'));
    }
}
