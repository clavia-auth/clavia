<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Deployment;

use Clavia\Configuration\Version;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The production kit (deploy/, docs/PRODUCTION.md) kept in step with the code it ships: the
 * production Caddyfile with the development one's security rules, both kits with every scheduled
 * command, and every place that names a release with the same version.
 */
final class DeploymentKitTest extends TestCase
{
    private const string ROOT = __DIR__ . '/../../..';

    /** The directives of a Caddyfile that are security rules. */
    private const string SECURITY_RULE = '/^(Strict-Transport-Security|X-Content-Type-Options|X-Frame-Options'
        . '|Referrer-Policy|-Status|Cache-Control "no-store"|@sensitive|handle \/(api|scim|auth\/static)'
        . '|try_files|@dashboard|redir \* \/dashboard)/';

    /** What the console's commands ask to be run on a schedule (their own descriptions say so). */
    private const array SCHEDULED = ['jobs:run', 'webhooks:deliver', 'audit:purge', 'clients:purge-unused'];

    /**
     * The development Caddyfile's lines that are security rules: the response headers, what is
     * kept out of shared caches, what each host refuses or serves, the one script PHP-FPM runs.
     *
     * @return iterable<string, array{string}>
     */
    public static function securityRules(): iterable
    {
        $seen = [];
        foreach (explode("\n", self::read('Caddyfile')) as $line) {
            $rule = trim($line);
            if (isset($seen[$rule])) {
                continue;
            }
            $seen[$rule] = true;
            if (preg_match(self::SECURITY_RULE, $rule) === 1) {
                yield $rule => [$rule];
            }
        }
    }

    #[DataProvider('securityRules')]
    public function testTheProductionCaddyfileKeepsEverySecurityRule(string $rule): void
    {
        $production = array_map('trim', explode("\n", self::read('deploy/helm/clavia/files/Caddyfile')));

        self::assertContains($rule, $production, 'deploy/helm/clavia/files/Caddyfile lost a rule.');
    }

    /** The leftmost X-Forwarded-For entries are the client's to write: read it right to left. */
    public function testTheClientAddressIsReadRightToLeft(): void
    {
        $production = array_map('trim', explode("\n", self::read('deploy/helm/clavia/files/Caddyfile')));

        self::assertContains('trusted_proxies_strict', $production);
    }

    public function testThereAreSecurityRulesToCompare(): void
    {
        self::assertGreaterThan(10, iterator_count(self::securityRules()), 'The development Caddyfile changed shape.');
    }

    public function testEveryScheduledCommandRunsInBothKits(): void
    {
        $scheduler = self::read('deploy/compose/scheduler.sh');
        $values = self::read('deploy/helm/clavia/values.yaml');
        $readme = self::read('docs/PRODUCTION.md');

        foreach (self::SCHEDULED as $command) {
            self::assertStringContainsString('run ' . $command, $scheduler, $command . ' in Compose.');
            self::assertStringContainsString('command: ' . $command, $values, $command . ' in the chart.');
            self::assertStringContainsString('bin/clavia ' . $command, $readme, $command . ' in the guide.');
        }
    }

    public function testEveryPlaceThatNamesTheReleaseNamesTheSameOne(): void
    {
        /** @var array{version: string} $composer */
        $composer = json_decode(self::read('composer.json'), true, 8, JSON_THROW_ON_ERROR);
        $version = $composer['version'];
        $chart = self::read('deploy/helm/clavia/Chart.yaml');
        $compose = self::read('deploy/compose/compose.yaml');
        $env = self::read('deploy/compose/env.example');

        self::assertSame($version, Version::CURRENT, 'src/Configuration/Version.php');
        self::assertStringContainsString("\nversion: " . $version . "\n", $chart, 'The chart\'s version.');
        self::assertStringContainsString("\nappVersion: \"" . $version . "\"\n", $chart, 'The chart\'s appVersion.');
        self::assertStringContainsString('${CLAVIA_VERSION:-' . $version . '}', $compose);
        self::assertStringContainsString('${CLAVIA_DASHBOARD_VERSION:-' . $version . '}', $compose);
        self::assertStringContainsString("CLAVIA_VERSION=" . $version . "\n", $env);
        self::assertStringContainsString("CLAVIA_DASHBOARD_VERSION=" . $version . "\n", $env);
    }

    private static function read(string $path): string
    {
        $content = file_get_contents(self::ROOT . '/' . $path);
        self::assertIsString($content, $path);

        return $content;
    }
}
