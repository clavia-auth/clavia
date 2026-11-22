<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Adapter\Secondary\Persistence\Migrations\SqlFileMigrator;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Application\Port\MigrationStatus;
use Clavia\Application\Port\SchemaMigrationFailed;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\IntegrationTestCase;

final class SqlFileMigratorTest extends IntegrationTestCase
{
    private Database $db;

    private string $directory = '';

    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->db = $this->scratchConnection();
        $this->clock = new FrozenClock('2026-11-20T09:00:00Z');
        $this->directory = sys_get_temp_dir() . '/clavia-migrations-' . bin2hex(random_bytes(6));
        mkdir($this->directory);
    }

    #[\Override]
    protected function tearDown(): void
    {
        $leftovers = glob($this->directory . '/*');
        array_map(unlink(...), $leftovers === false ? [] : $leftovers);
        rmdir($this->directory);

        parent::tearDown();
    }

    public function testItAppliesPendingMigrationsInOrderAndRecordsThem(): void
    {
        // Written out of order on purpose: the version decides, not the directory listing.
        $this->file('0002_add_email.sql', 'ALTER TABLE users ADD COLUMN email text;');
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');

        $applied = $this->migrator()->migrate();

        self::assertSame(['0001 create_users', '0002 add_email'], $this->describe($applied));
        self::assertTrue($applied[0]->isApplied());
        self::assertSame('2026-11-20T09:00:00+00:00', $applied[0]->appliedAt?->format(DATE_ATOM));
        self::assertSame(0, $this->db->fetchValue('SELECT count(email) FROM users'));
        self::assertSame(
            [['version' => '0001', 'name' => 'create_users'], ['version' => '0002', 'name' => 'add_email']],
            $this->db->fetchAll('SELECT version, name FROM schema_migrations ORDER BY version'),
        );
    }

    public function testRunningAgainDoesNothing(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->migrator()->migrate();

        self::assertSame([], $this->migrator()->migrate());
    }

    public function testOnlyWhatIsNewIsApplied(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->migrator()->migrate();
        $this->file('0002_create_clients.sql', 'CREATE TABLE clients (id text PRIMARY KEY);');
        $this->clock->advance(3600);

        $applied = $this->migrator()->migrate();

        self::assertSame(['0002 create_clients'], $this->describe($applied));
        self::assertSame('2026-11-20T10:00:00+00:00', $applied[0]->appliedAt?->format(DATE_ATOM));
    }

    public function testAnEmptyDirectoryIsUpToDate(): void
    {
        self::assertSame([], $this->migrator()->migrate());
        self::assertSame([], $this->migrator()->status());
    }

    public function testStatusListsAppliedAndPendingWithoutChangingAnything(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->migrator()->migrate();
        $this->file('0002_create_clients.sql', 'CREATE TABLE clients (id text PRIMARY KEY);');

        $status = $this->migrator()->status();

        self::assertSame(['0001 create_users', '0002 create_clients'], $this->describe($status));
        self::assertTrue($status[0]->isApplied());
        self::assertSame('2026-11-20T09:00:00+00:00', $status[0]->appliedAt?->format(DATE_ATOM));
        self::assertFalse($status[1]->isApplied());
        self::assertNull($this->db->fetchValue("SELECT to_regclass('clients')"));
    }

    public function testStatusOnADatabaseNeverMigratedCreatesNothing(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');

        $status = $this->migrator()->status();

        self::assertFalse($status[0]->isApplied());
        self::assertNull($this->db->fetchValue("SELECT to_regclass('schema_migrations')"));
    }

    public function testAFailingMigrationIsRolledBackEntirelyAndStopsTheRun(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->file(
            '0002_broken.sql',
            'CREATE TABLE half_done (id integer PRIMARY KEY); ALTER TABLE no_such_table ADD COLUMN x text;',
        );
        $this->file('0003_create_clients.sql', 'CREATE TABLE clients (id text PRIMARY KEY);');

        try {
            $this->migrator()->migrate();
            self::fail('A broken migration was reported as applied.');
        } catch (SchemaMigrationFailed $failure) {
            self::assertStringContainsString('0002_broken failed and was rolled back', $failure->getMessage());
            self::assertStringContainsString('no_such_table', $failure->getMessage());
        }

        // The DDL before the error is gone too, 0001 stays, and 0003 was never attempted.
        self::assertNull($this->db->fetchValue("SELECT to_regclass('half_done')"));
        self::assertNull($this->db->fetchValue("SELECT to_regclass('clients')"));
        self::assertSame([['version' => '0001']], $this->db->fetchAll('SELECT version FROM schema_migrations'));
        self::assertFalse($this->db->inTransaction());
    }

    public function testFixingTheBrokenMigrationLetsTheRunResume(): void
    {
        $this->file('0001_broken.sql', 'ALTER TABLE no_such_table ADD COLUMN x text;');
        try {
            $this->migrator()->migrate();
        } catch (SchemaMigrationFailed) {
            // expected
        }

        // Never applied, so it is not immutable yet.
        $this->file('0001_broken.sql', 'CREATE TABLE fixed (id integer PRIMARY KEY);');

        self::assertSame(['0001 broken'], $this->describe($this->migrator()->migrate()));
    }

    public function testAnAppliedMigrationThatWasEditedIsRefused(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->migrator()->migrate();
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id bigint PRIMARY KEY);');

        foreach (['migrate', 'status'] as $operation) {
            try {
                $this->migrator()->{$operation}();
                self::fail(sprintf('%s accepted an edited migration.', $operation));
            } catch (SchemaMigrationFailed $failure) {
                self::assertStringContainsString('was modified after it was applied', $failure->getMessage());
            }
        }
    }

    public function testAnAppliedMigrationMissingFromDiskIsRefused(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $this->migrator()->migrate();
        unlink($this->directory . '/0001_create_users.sql');

        $this->expectException(SchemaMigrationFailed::class);
        $this->expectExceptionMessageIsOrContains('0001_create_users is recorded as applied but its file is not in');

        $this->migrator()->migrate();
    }

    public function testAPendingMigrationOlderThanAnAppliedOneIsRefused(): void
    {
        $this->file('0002_create_clients.sql', 'CREATE TABLE clients (id text PRIMARY KEY);');
        $this->migrator()->migrate();
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');

        $this->expectException(SchemaMigrationFailed::class);
        $this->expectExceptionMessageIsOrContains('0001_create_users is pending but older than 0002');

        $this->migrator()->migrate();
    }

    public function testTwoFilesCannotShareAVersion(): void
    {
        $this->file('0001_create_users.sql', 'SELECT 1;');
        $this->file('0001_create_clients.sql', 'SELECT 1;');

        $this->expectException(SchemaMigrationFailed::class);
        $this->expectExceptionMessageIsOrContains('Two migrations share version 0001');

        $this->migrator()->status();
    }

    public function testAFileThatDoesNotFollowTheNamingRuleIsRefusedNotSkipped(): void
    {
        foreach (['1_short_version.sql', '0001-dashes.sql', '0001_Upper.sql', 'no_version.sql'] as $name) {
            $this->file($name, 'SELECT 1;');

            try {
                $this->migrator()->status();
                self::fail(sprintf('%s was accepted.', $name));
            } catch (SchemaMigrationFailed $failure) {
                self::assertStringContainsString($name . ' is not named <version>_<name>.sql', $failure->getMessage());
            }

            unlink($this->directory . '/' . $name);
        }
    }

    public function testVersionsAreOrderedAsNumbersWhateverTheirWidth(): void
    {
        $this->file('10000_third.sql', 'CREATE TABLE third (id integer);');
        $this->file('0002_first.sql', 'CREATE TABLE first (id integer);');
        $this->file('9999_second.sql', 'CREATE TABLE second (id integer);');

        self::assertSame(['0002 first', '9999 second', '10000 third'], $this->describe($this->migrator()->migrate()));
        self::assertSame(['0002 first', '9999 second', '10000 third'], $this->describe($this->migrator()->status()));
    }

    public function testAMissingDirectoryIsAnErrorNotAnEmptyHistory(): void
    {
        $migrator = new SqlFileMigrator($this->db, $this->directory . '/nowhere', $this->clock);

        $this->expectException(SchemaMigrationFailed::class);
        $this->expectExceptionMessageIsOrContains('does not exist');

        $migrator->migrate();
    }

    public function testTheAdvisoryLockIsReleasedEvenWhenTheRunFails(): void
    {
        $this->file('0001_broken.sql', 'ALTER TABLE no_such_table ADD COLUMN x text;');
        try {
            $this->migrator()->migrate();
        } catch (SchemaMigrationFailed) {
            // expected
        }

        // A second session can take the same lock at once: nothing is left holding it.
        $other = $this->scratchConnection();
        self::assertTrue($other->fetchValue('SELECT pg_try_advisory_lock(:key)', ['key' => 0x436C6176]));
        $other->fetchValue('SELECT pg_advisory_unlock(:key)', ['key' => 0x436C6176]);
    }

    public function testASecondRunnerWaitsItsTurnInsteadOfApplyingTwice(): void
    {
        $this->file('0001_create_users.sql', 'CREATE TABLE users (id integer PRIMARY KEY);');
        $other = $this->scratchConnection();

        // Another deploy holds the lock: this runner must not get past it.
        $other->fetchValue('SELECT pg_advisory_lock(:key)', ['key' => 0x436C6176]);
        $this->db->executeScript("SET lock_timeout = '300ms'");

        try {
            $this->migrator()->migrate();
            self::fail('The migrator ran while another runner held the lock.');
        } catch (\Throwable $blocked) {
            self::assertStringContainsString('lock timeout', $blocked->getMessage());
        } finally {
            $other->fetchValue('SELECT pg_advisory_unlock(:key)', ['key' => 0x436C6176]);
        }

        self::assertNull($this->db->fetchValue("SELECT to_regclass('users')"));
    }

    private function migrator(): SqlFileMigrator
    {
        return new SqlFileMigrator($this->db, $this->directory, $this->clock);
    }

    private function file(string $name, string $sql): void
    {
        file_put_contents($this->directory . '/' . $name, $sql);
    }

    /**
     * @param list<MigrationStatus> $migrations
     *
     * @return list<string>
     */
    private function describe(array $migrations): array
    {
        return array_map(static fn (MigrationStatus $m): string => $m->version . ' ' . $m->name, $migrations);
    }
}
