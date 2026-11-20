<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Bootstrap;

use Clavia\Bootstrap\EnvironmentVariables;
use PHPUnit\Framework\TestCase;

final class EnvironmentVariablesTest extends TestCase
{
    private string $root = '';

    #[\Override]
    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/clavia-env-' . bin2hex(random_bytes(6));
        mkdir($this->root);
    }

    #[\Override]
    protected function tearDown(): void
    {
        @unlink($this->root . '/.env');
        rmdir($this->root);
    }

    public function testTheProcessEnvironmentWinsOverTheFile(): void
    {
        file_put_contents($this->root . '/.env', "CLAVIA_ROOT_DOMAIN=file.com\nCLAVIA_ENV=staging\n");

        $variables = EnvironmentVariables::load($this->root, ['CLAVIA_ROOT_DOMAIN' => 'process.com']);

        self::assertSame(['CLAVIA_ROOT_DOMAIN' => 'process.com', 'CLAVIA_ENV' => 'staging'], $variables);
    }

    public function testOnlyClaviaVariablesAreKept(): void
    {
        file_put_contents($this->root . '/.env', "PATH=/tmp\nCLAVIA_ROOT_DOMAIN=acme.com\n");

        $variables = EnvironmentVariables::load($this->root, ['HOME' => '/root', 'CLAVIA_ENV' => 'development']);

        self::assertSame(['CLAVIA_ROOT_DOMAIN' => 'acme.com', 'CLAVIA_ENV' => 'development'], $variables);
    }

    public function testCommentsQuotesAndBlankLinesAreUnderstood(): void
    {
        file_put_contents(
            $this->root . '/.env',
            "# a comment\n\nCLAVIA_ROOT_DOMAIN=\"acme.com\"\nCLAVIA_SECRET_ENCRYPTION_KEY=\n# CLAVIA_ENV=production\n",
        );

        $variables = EnvironmentVariables::load($this->root, []);

        self::assertSame(['CLAVIA_ROOT_DOMAIN' => 'acme.com', 'CLAVIA_SECRET_ENCRYPTION_KEY' => ''], $variables);
    }

    public function testAMissingFileIsNotAnError(): void
    {
        $variables = EnvironmentVariables::load($this->root, ['CLAVIA_ENV' => 'staging']);

        self::assertSame(['CLAVIA_ENV' => 'staging'], $variables);
    }

    public function testTheFileIsNeverExportedIntoTheProcessEnvironment(): void
    {
        file_put_contents($this->root . '/.env', "CLAVIA_NOT_EXPORTED=1\n");

        EnvironmentVariables::load($this->root, []);

        self::assertFalse(getenv('CLAVIA_NOT_EXPORTED'));
        self::assertArrayNotHasKey('CLAVIA_NOT_EXPORTED', $_ENV);
        self::assertArrayNotHasKey('CLAVIA_NOT_EXPORTED', $_SERVER);
    }
}
