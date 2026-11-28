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
use Symfony\Component\Yaml\Yaml;

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
        . '|Referrer-Policy|-Status|Cache-Control "no-store"|@sensitive|handle \/(api|scim|auth\/static|metrics)'
        . '|try_files|@dashboard|redir \* \/dashboard)/';

    /** What the console's commands ask to be run on a schedule (their own descriptions say so). */
    private const array SCHEDULED = ['jobs:run', 'webhooks:deliver', 'fga:sync', 'audit:purge', 'clients:purge-unused'];

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

    /** Only the internal listener marks its requests: /metrics answers nowhere else (#23). */
    public function testOnlyTheInternalListenerMarksItsRequests(): void
    {
        foreach (['Caddyfile', 'deploy/helm/clavia/files/Caddyfile'] as $path) {
            $caddyfile = self::read($path);

            self::assertSame(1, substr_count($caddyfile, 'env CLAVIA_LISTENER internal'), $path);
            self::assertSame(2, substr_count($caddyfile, 'import clavia_internal'), $path . ': /healthz and /metrics.');
            $refused = substr_count($caddyfile, "handle /metrics {\n\t\trespond 404");
            self::assertSame(2, $refused, $path . ': both hosts.');
        }
    }

    /**
     * The image carries every directory the server reads when it runs: one missing is a release that
     * cannot start (a language without its catalogue is refused at boot) or cannot render a page.
     */
    public function testTheImageCarriesEveryDirectoryTheServerReads(): void
    {
        $dockerfile = self::read('docker/php/Dockerfile');

        $read = ['bin', 'config', 'migrations', 'public', 'src', 'templates', 'translations', 'docs/openapi'];
        foreach ($read as $path) {
            self::assertStringContainsString(sprintf('COPY --from=app %s ./%s', $path, $path), $dockerfile, $path);
        }
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

    /**
     * OpenFGA answers Clavia's decisions, so wherever it runs it is the same engine set up the same
     * way (docs/design/fine-grained-authorization.md §2): one pinned version, its own database, the
     * preshared key, every cache off for strongly consistent answers, no playground, nothing published.
     *
     * @return iterable<string, array{string}>
     */
    public static function composeFilesRunningOpenFga(): iterable
    {
        yield 'development' => ['docker-compose.yml'];
        yield 'end to end' => ['test/e2e/compose.yaml'];
        yield 'production' => ['deploy/compose/compose.yaml'];
    }

    #[DataProvider('composeFilesRunningOpenFga')]
    public function testOpenFgaIsSetUpAlikeWhereverItRuns(string $path): void
    {
        $services = self::services($path);
        $reference = self::services('docker-compose.yml');

        foreach (['openfga-db', 'openfga-migrate', 'openfga'] as $name) {
            self::assertArrayHasKey($name, $services, $name . ' in ' . $path);
            self::assertArrayNotHasKey('ports', $services[$name], $name . ' publishes nothing in ' . $path);
        }
        foreach (['openfga-migrate', 'openfga'] as $name) {
            self::assertSame(
                $reference[$name]['image'] ?? null,
                $services[$name]['image'] ?? null,
                $name . ' in ' . $path,
            );
        }
        self::assertSame('migrate', $services['openfga-migrate']['command'] ?? null);
        $dependsOn = $services['openfga']['depends_on'] ?? [];
        self::assertSame(
            'service_completed_successfully',
            $dependsOn['openfga-migrate']['condition'] ?? null,
            'OpenFGA starts on a migrated schema in ' . $path,
        );
        $environment = $services['openfga']['environment'] ?? [];
        foreach (
            [
                'OPENFGA_DATASTORE_ENGINE' => 'postgres',
                'OPENFGA_AUTHN_METHOD' => 'preshared',
                'OPENFGA_CHECK_QUERY_CACHE_ENABLED' => 'false',
                'OPENFGA_CHECK_ITERATOR_CACHE_ENABLED' => 'false',
                'OPENFGA_LIST_OBJECTS_ITERATOR_CACHE_ENABLED' => 'false',
                'OPENFGA_PLAYGROUND_ENABLED' => 'false',
            ] as $variable => $value
        ) {
            self::assertSame($value, $environment[$variable] ?? null, $variable . ' in ' . $path);
        }
        self::assertNotEmpty($environment['OPENFGA_AUTHN_PRESHARED_KEYS'] ?? null, 'The key, in ' . $path);
    }

    public function testTheProductionKitRunsOpenFgaOnlyWhenAskedTo(): void
    {
        $services = self::services('deploy/compose/compose.yaml');

        foreach (['openfga-db', 'openfga-migrate', 'openfga'] as $name) {
            self::assertSame(['fga'], $services[$name]['profiles'] ?? null, $name);
        }
        foreach (['php', 'scheduler'] as $name) {
            // Waited for with the profile, and no dependency without it.
            $dependsOn = $services[$name]['depends_on'] ?? [];
            self::assertFalse($dependsOn['openfga']['required'] ?? true, $name);
        }
    }

    /**
     * The services of a Compose file, as far as these tests read them.
     *
     * @return array<string, array{image?: string, command?: string|list<string>, ports?: list<string>,
     *     profiles?: list<string>, environment?: array<string, string>,
     *     depends_on?: array<string, array{condition?: string, required?: bool}>}>
     */
    private static function services(string $path): array
    {
        /** @var array{services: array<string, array{image?: string, command?: string|list<string>,
         *     ports?: list<string>, profiles?: list<string>, environment?: array<string, string>,
         *     depends_on?: array<string, array{condition?: string, required?: bool}>}>} $compose */
        $compose = Yaml::parse(self::read($path));

        return $compose['services'];
    }

    private static function read(string $path): string
    {
        $content = file_get_contents(self::ROOT . '/' . $path);
        self::assertIsString($content, $path);

        return $content;
    }
}
