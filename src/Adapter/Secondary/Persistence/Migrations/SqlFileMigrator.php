<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\Migrations;

use Clavia\Application\Port\MigrationStatus;
use Clavia\Application\Port\SchemaMigrationFailed;
use Clavia\Application\Port\SchemaMigrator;
use Clavia\Domain\Shared\Clock;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use DateTimeImmutable;
use DateTimeInterface;
use Throwable;

/**
 * Applies the plain SQL files in `migrations/`, in order, once each.
 *
 * A migration is a file named `<version>_<name>.sql` — `0003_refresh_tokens.sql`. The
 * version is digits (at least four, zero-padded so the directory lists in order); the
 * name is lower-case words joined by underscores. What has been applied is recorded in
 * the `schema_migrations` table, with a checksum of the file as it was applied.
 *
 * The rules, all enforced before anything is run:
 *
 * - **Applied migrations are immutable.** A file whose checksum no longer matches the
 *   one recorded, or an applied migration missing from disk, stops everything: the
 *   database was built from something this checkout does not contain.
 * - **History is linear.** A pending migration older than the newest applied one is
 *   refused — it would run against a schema it was not written for. Renumber it.
 * - **Each migration is one transaction**, DDL included (PostgreSQL makes DDL
 *   transactional), together with the row that records it: a migration is entirely
 *   applied and recorded, or not at all.
 * - **One runner at a time.** A session-level advisory lock serialises concurrent
 *   deploys; the second waits, then finds nothing left to do.
 *
 * There are no "down" migrations. Undoing a change is a new migration.
 */
final readonly class SqlFileMigrator implements SchemaMigrator
{
    public const string TABLE = 'schema_migrations';

    private const string FILE_PATTERN = '/^(?<version>\d{4,})_(?<name>[a-z0-9]+(?:_[a-z0-9]+)*)\.sql$/D';

    /** Arbitrary but fixed: "Clav" in ASCII. Identifies this lock among PostgreSQL's advisory locks. */
    private const int ADVISORY_LOCK_KEY = 0x436C6176;

    public function __construct(
        private Database $database,
        private string $directory,
        private Clock $clock,
    ) {
    }

    #[\Override]
    public function migrate(): array
    {
        $this->database->fetchValue('SELECT pg_advisory_lock(:key)', ['key' => self::ADVISORY_LOCK_KEY]);

        try {
            $this->database->executeScript(sprintf(
                'CREATE TABLE IF NOT EXISTS %s ('
                . 'version text PRIMARY KEY, name text NOT NULL, checksum text NOT NULL, '
                . 'applied_at timestamptz NOT NULL)',
                self::TABLE,
            ));

            $applied = [];
            foreach ($this->plan() as $migration) {
                if ($migration['status']->isApplied()) {
                    continue;
                }

                $applied[] = $this->apply($migration['status'], $migration['file'], $migration['checksum']);
            }

            return $applied;
        } finally {
            $this->database->fetchValue('SELECT pg_advisory_unlock(:key)', ['key' => self::ADVISORY_LOCK_KEY]);
        }
    }

    #[\Override]
    public function status(): array
    {
        return array_column($this->plan(), 'status');
    }

    /**
     * @param non-empty-string $checksum
     *
     * @throws SchemaMigrationFailed
     */
    private function apply(MigrationStatus $pending, string $file, string $checksum): MigrationStatus
    {
        $appliedAt = $this->clock->now();
        $sql = (string) file_get_contents($file);

        $this->database->beginTransaction();

        try {
            $this->database->executeScript($sql);
            $this->database->execute(
                sprintf(
                    'INSERT INTO %s (version, name, checksum, applied_at) '
                    . 'VALUES (:version, :name, :checksum, :applied_at)',
                    self::TABLE,
                ),
                [
                    'version' => $pending->version,
                    'name' => $pending->name,
                    'checksum' => $checksum,
                    'applied_at' => $appliedAt->format(DateTimeInterface::RFC3339_EXTENDED),
                ],
            );
            $this->database->commit();
        } catch (Throwable $failure) {
            if ($this->database->inTransaction()) {
                $this->database->rollBack();
            }

            throw new SchemaMigrationFailed(
                sprintf(
                    'Migration %s_%s failed and was rolled back: %s',
                    $pending->version,
                    $pending->name,
                    $failure->getMessage(),
                ),
                previous: $failure,
            );
        }

        return new MigrationStatus($pending->version, $pending->name, $appliedAt);
    }

    /**
     * Every migration on disk, oldest first, checked against the recorded history.
     *
     * @return list<array{status: MigrationStatus, file: string, checksum: non-empty-string}>
     *
     * @throws SchemaMigrationFailed
     */
    private function plan(): array
    {
        $files = $this->files();
        $recorded = $this->recorded();

        foreach ($recorded as $version => $row) {
            $version = (string) $version;
            if (! isset($files[$version])) {
                throw new SchemaMigrationFailed(sprintf(
                    'Migration %s_%s is recorded as applied but its file is not in %s.',
                    $version,
                    $row['name'],
                    $this->directory,
                ));
            }
            if (! hash_equals($row['checksum'], $files[$version]['checksum'])) {
                throw new SchemaMigrationFailed(sprintf(
                    'Migration %s_%s was modified after it was applied. Applied migrations are immutable: '
                    . 'restore the file and put the change in a new migration.',
                    $version,
                    $files[$version]['name'],
                ));
            }
        }

        $newestApplied = array_key_last($recorded);
        $newestApplied = $newestApplied === null ? null : (string) $newestApplied;
        $plan = [];

        foreach ($files as $version => $file) {
            $version = (string) $version;
            assert($version !== '');
            $appliedAt = $recorded[$version]['applied_at'] ?? null;

            if ($appliedAt === null && $newestApplied !== null && strnatcmp($version, $newestApplied) < 0) {
                throw new SchemaMigrationFailed(sprintf(
                    'Migration %s_%s is pending but older than %s, which is already applied. '
                    . 'History is linear: renumber it after the newest migration.',
                    $version,
                    $file['name'],
                    $newestApplied,
                ));
            }

            $plan[] = [
                'status' => new MigrationStatus($version, $file['name'], $appliedAt),
                'file' => $file['path'],
                'checksum' => $file['checksum'],
            ];
        }

        return $plan;
    }

    /**
     * @return array<array-key, array{name: non-empty-string, path: string, checksum: non-empty-string}>
     *         Keyed by version, oldest first. PHP turns an all-digit key with no leading zero into
     *         an integer, so readers cast the key back to a string.
     *
     * @throws SchemaMigrationFailed
     */
    private function files(): array
    {
        if (! is_dir($this->directory)) {
            throw new SchemaMigrationFailed(sprintf('The migrations directory %s does not exist.', $this->directory));
        }

        $files = [];
        $paths = glob($this->directory . '/*.sql');
        foreach ($paths === false ? [] : $paths as $path) {
            if (preg_match(self::FILE_PATTERN, basename($path), $match) !== 1) {
                throw new SchemaMigrationFailed(sprintf(
                    'Migration file %s is not named <version>_<name>.sql, e.g. 0003_refresh_tokens.sql.',
                    basename($path),
                ));
            }

            /** @var non-empty-string $version */
            $version = $match['version'];
            /** @var non-empty-string $name */
            $name = $match['name'];

            if (isset($files[$version])) {
                throw new SchemaMigrationFailed(sprintf(
                    'Two migrations share version %s: %s and %s.',
                    $version,
                    $files[$version]['name'],
                    $name,
                ));
            }

            $checksum = hash_file('sha256', $path);
            if ($checksum === false) {
                throw new SchemaMigrationFailed(sprintf('Migration file %s cannot be read.', basename($path)));
            }

            $files[$version] = ['name' => $name, 'path' => $path, 'checksum' => $checksum];
        }

        uksort($files, self::byVersion(...));

        return $files;
    }

    private static function byVersion(int|string $a, int|string $b): int
    {
        return strnatcmp((string) $a, (string) $b);
    }

    /**
     * @return array<array-key, array{name: string, checksum: string, applied_at: DateTimeImmutable}>
     *         Keyed by version, oldest first. Empty when nothing was ever migrated.
     */
    private function recorded(): array
    {
        $exists = $this->database->fetchValue('SELECT to_regclass(:table) IS NOT NULL', ['table' => self::TABLE]);
        if ($exists !== true) {
            return [];
        }

        $recorded = [];
        $rows = $this->database->fetchAll(
            sprintf('SELECT version, name, checksum, applied_at FROM %s', self::TABLE),
        );

        /** @var array{version: string, name: string, checksum: string, applied_at: string} $row */
        foreach ($rows as $row) {
            $recorded[$row['version']] = [
                'name' => $row['name'],
                'checksum' => $row['checksum'],
                'applied_at' => new DateTimeImmutable($row['applied_at']),
            ];
        }

        uksort($recorded, self::byVersion(...));

        return $recorded;
    }
}
