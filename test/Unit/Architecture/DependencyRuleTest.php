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
 * The cheap, unarguable half of the hexagonal rules (the rest is deptrac.yaml).
 *
 * The domain imports nothing but itself and PHP; the application layer imports the
 * domain and itself; the settings are plain data. A third-party name in any of them —
 * a PSR interface included — fails here.
 */
final class DependencyRuleTest extends TestCase
{
    public function testTheDomainImportsNothingOutsideItself(): void
    {
        self::assertSame([], $this->foreignImports('src/Domain', ['Clavia\\Domain\\']));
    }

    public function testTheApplicationLayerImportsOnlyTheDomain(): void
    {
        self::assertSame([], $this->foreignImports('src/Application', ['Clavia\\Domain\\', 'Clavia\\Application\\']));
    }

    public function testTheSettingsDependOnNoRingAndNoLibrary(): void
    {
        self::assertSame([], $this->foreignImports('src/Configuration', ['Clavia\\Configuration\\']));
    }

    public function testTheDrivingAdaptersNeverReachADrivenAdapter(): void
    {
        $offenders = [];
        foreach (SourceFiles::in(['src/Ui']) as $file) {
            foreach (SourceFiles::imports($file) as $import) {
                $reachesInfrastructure = str_starts_with($import, 'Clavia\\Infrastructure\\');
                $reachesBootstrap = str_starts_with($import, 'Clavia\\Bootstrap\\');

                if ($reachesInfrastructure || $reachesBootstrap) {
                    $offenders[] = sprintf('%s imports %s', $this->relative($file), $import);
                }
            }
        }

        self::assertSame([], $offenders);
    }

    public function testTheImportScannerSeesWhatAFileImports(): void
    {
        $imports = SourceFiles::imports(SourceFiles::PROJECT_ROOT . '/src/Ui/Http/Shared/HealthHandler.php');

        self::assertContains('Psr\\Http\\Server\\RequestHandlerInterface', $imports);
    }

    /**
     * @param list<string> $allowedPrefixes
     *
     * @return list<string> One line per import that is neither allowed nor a PHP built-in.
     */
    private function foreignImports(string $directory, array $allowedPrefixes): array
    {
        $offenders = [];

        foreach (SourceFiles::in([$directory]) as $file) {
            foreach (SourceFiles::imports($file) as $import) {
                $allowed = array_any(
                    $allowedPrefixes,
                    static fn (string $prefix): bool => str_starts_with($import, $prefix),
                );
                // A global name (no namespace separator) is PHP's own: Throwable, Attribute, …
                $builtIn = ! str_contains($import, '\\') || $this->isInternal($import);

                if (! $allowed && ! $builtIn) {
                    $offenders[] = sprintf('%s imports %s', $this->relative($file), $import);
                }
            }
        }

        return $offenders;
    }

    /** Namespaced classes PHP itself ships, such as Uri\Rfc3986\Uri or Random\Randomizer. */
    private function isInternal(string $name): bool
    {
        return (class_exists($name) || interface_exists($name) || enum_exists($name))
            && new \ReflectionClass($name)->isInternal();
    }

    private function relative(string $file): string
    {
        return substr((string) realpath($file), strlen((string) realpath(SourceFiles::PROJECT_ROOT)) + 1);
    }
}
