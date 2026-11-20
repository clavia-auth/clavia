<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\MigrationStatus;
use Clavia\Application\Port\SchemaMigrationFailed;
use Clavia\Application\Port\SchemaMigrator;
use DateTimeImmutable;

/**
 * A migrator with a scripted history and no database.
 */
final class FakeSchemaMigrator implements SchemaMigrator
{
    public ?string $failure = null;

    /**
     * @param list<MigrationStatus> $migrations
     */
    public function __construct(private array $migrations = [])
    {
    }

    #[\Override]
    public function migrate(): array
    {
        $this->guard();

        $applied = [];
        foreach ($this->migrations as $index => $migration) {
            if (! $migration->isApplied()) {
                $applied[] = $this->migrations[$index] = new MigrationStatus(
                    $migration->version,
                    $migration->name,
                    new DateTimeImmutable('2026-11-20T09:00:00Z'),
                );
            }
        }

        return $applied;
    }

    #[\Override]
    public function status(): array
    {
        $this->guard();

        return $this->migrations;
    }

    private function guard(): void
    {
        if ($this->failure !== null) {
            throw new SchemaMigrationFailed($this->failure);
        }
    }
}
