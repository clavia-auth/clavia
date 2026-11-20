<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Application\Port\MigrationStatus;
use Clavia\Adapter\Primary\Cli\DatabaseStatusCommand;
use Clavia\Adapter\Primary\Cli\MigrateDatabaseCommand;
use ClaviaTest\Support\Fake\FakeSchemaMigrator;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class DatabaseCommandsTest extends TestCase
{
    public function testMigrateNamesWhatItApplied(): void
    {
        $tester = new CommandTester(new MigrateDatabaseCommand(new FakeSchemaMigrator([
            $this->applied('0001', 'create_users'),
            $this->pending('0002', 'create_clients'),
            $this->pending('0003', 'refresh_tokens'),
        ])));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame("Applied 0002_create_clients\nApplied 0003_refresh_tokens\n", $tester->getDisplay(true));
    }

    public function testMigrateSaysSoWhenThereIsNothingToDo(): void
    {
        $tester = new CommandTester(new MigrateDatabaseCommand(new FakeSchemaMigrator([
            $this->applied('0001', 'create_users'),
        ])));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame("Already up to date.\n", $tester->getDisplay(true));
    }

    public function testMigrateReportsAFailureAndExitsNonZero(): void
    {
        $migrator = new FakeSchemaMigrator();
        $migrator->failure = 'Migration 0002_broken failed and was rolled back: syntax error';
        $tester = new CommandTester(new MigrateDatabaseCommand($migrator));

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString('0002_broken failed and was rolled back', $tester->getDisplay(true));
    }

    public function testStatusListsEveryMigration(): void
    {
        $tester = new CommandTester(new DatabaseStatusCommand(new FakeSchemaMigrator([
            $this->applied('0001', 'create_users'),
        ])));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertMatchesRegularExpression(
            '/\| 0001\s+\| create_users\s+\| 2026-11-19T08:30:00\+00:00\s+\|/',
            $tester->getDisplay(true),
        );
    }

    public function testStatusExitsWithADistinctCodeWhenMigrationsArePending(): void
    {
        $tester = new CommandTester(new DatabaseStatusCommand(new FakeSchemaMigrator([
            $this->applied('0001', 'create_users'),
            $this->pending('0002', 'create_clients'),
        ])));

        self::assertSame(DatabaseStatusCommand::PENDING, $tester->execute([]));
        self::assertMatchesRegularExpression(
            '/\| 0002\s+\| create_clients\s+\| pending\s+\|/',
            $tester->getDisplay(true),
        );
        self::assertStringContainsString('1 pending. Run `clavia db:migrate`.', $tester->getDisplay(true));
    }

    public function testStatusWithNoMigrationsAtAll(): void
    {
        $tester = new CommandTester(new DatabaseStatusCommand(new FakeSchemaMigrator()));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame("No migrations.\n", $tester->getDisplay(true));
    }

    public function testStatusReportsAnUntrustworthyHistory(): void
    {
        $migrator = new FakeSchemaMigrator();
        $migrator->failure = 'Migration 0001_create_users was modified after it was applied.';
        $tester = new CommandTester(new DatabaseStatusCommand($migrator));

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString('was modified after it was applied', $tester->getDisplay(true));
    }

    /**
     * @param non-empty-string $version
     * @param non-empty-string $name
     */
    private function applied(string $version, string $name): MigrationStatus
    {
        return new MigrationStatus($version, $name, new DateTimeImmutable('2026-11-19T08:30:00Z'));
    }

    /**
     * @param non-empty-string $version
     * @param non-empty-string $name
     */
    private function pending(string $version, string $name): MigrationStatus
    {
        return new MigrationStatus($version, $name, null);
    }
}
