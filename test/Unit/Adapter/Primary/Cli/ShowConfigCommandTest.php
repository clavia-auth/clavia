<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\ShowConfigCommand;
use Clavia\Configuration\Settings;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Symfony\Component\Console\Tester\CommandTester;

final class ShowConfigCommandTest extends TestCase
{
    private const array VARIABLES = [
        'CLAVIA_ROOT_DOMAIN' => 'acme.com',
        'CLAVIA_POSTGRES_PASSWORD' => 'hunter2',
        'CLAVIA_GOOGLE_CLIENT_SECRET' => 'g-secret',
        'CLAVIA_SECRET_ENCRYPTION_KEY' => 'c2VjcmV0',
        'CLAVIA_SMTP_PASSWORD' => 'smtp-pass',
    ];

    public function testEverySettingIsPrintedUnderItsVariableName(): void
    {
        $lines = $this->printed([]);
        $parameters = new ReflectionClass(Settings::class)->getConstructor()?->getParameters() ?? [];

        self::assertCount(count($parameters), $lines);
        foreach ($parameters as $parameter) {
            self::assertArrayHasKey(Settings::variableName($parameter->getName()), $lines);
        }

        self::assertSame('acme.com', $lines['CLAVIA_ROOT_DOMAIN']);
        self::assertSame('development', $lines['CLAVIA_ENV']);
        self::assertSame('https://auth.acme.com', $lines['CLAVIA_ISSUER_URL']);
        self::assertSame('true', $lines['CLAVIA_SESSION_COOKIE_SECURE']);
        self::assertSame('["openid","profile","email"]', $lines['CLAVIA_SCOPES_SUPPORTED']);
        self::assertSame('<unset>', $lines['CLAVIA_SIGNING_KEY_REF']);
    }

    public function testCredentialsAreMaskedByDefault(): void
    {
        $lines = $this->printed([]);

        self::assertSame('***', $lines['CLAVIA_POSTGRES_PASSWORD']);
        self::assertSame('***', $lines['CLAVIA_GOOGLE_CLIENT_SECRET']);
        self::assertSame('***', $lines['CLAVIA_SECRET_ENCRYPTION_KEY']);
        self::assertSame('***', $lines['CLAVIA_SMTP_PASSWORD']);
        self::assertSame('<unset>', $lines['CLAVIA_GITHUB_CLIENT_SECRET']);
        // A URL keeps its host and database: they matter when diagnosing a misconfiguration.
        self::assertSame('postgresql://clavia:***@localhost:5433/clavia', $lines['CLAVIA_DATABASE_URL']);
        self::assertStringNotContainsString('hunter2', implode("\n", $lines));
    }

    public function testCredentialsAreShownOnRequest(): void
    {
        $lines = $this->printed(['--show-secrets' => true]);

        self::assertSame('hunter2', $lines['CLAVIA_POSTGRES_PASSWORD']);
        self::assertSame('postgresql://clavia:hunter2@localhost:5433/clavia', $lines['CLAVIA_DATABASE_URL']);
    }

    /**
     * @param array<string, bool> $input
     *
     * @return array<string, string> Variable name to printed value.
     */
    private function printed(array $input): array
    {
        $tester = new CommandTester(new ShowConfigCommand(Settings::fromEnvironment(self::VARIABLES)));
        $tester->execute($input);
        $tester->assertCommandIsSuccessful();

        $lines = [];
        foreach (explode("\n", trim($tester->getDisplay())) as $line) {
            [$name, $value] = array_pad(explode(' ', $line, 2), 2, '');
            $lines[$name] = trim($value);
        }

        return $lines;
    }
}
