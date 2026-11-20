<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Port\SchemaMigrationFailed;
use Clavia\Application\Port\SchemaMigrator;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia db:migrate` — bring the database schema up to date.
 *
 * Applies the pending files of `migrations/`, oldest first, each in its own
 * transaction. Safe to run on every deploy and from several instances at once.
 */
#[AsCommand(name: 'db:migrate', description: 'Apply the pending database migrations.')]
final class MigrateDatabaseCommand extends Command
{
    public function __construct(private readonly SchemaMigrator $migrator)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $applied = $this->migrator->migrate();
        } catch (SchemaMigrationFailed $failure) {
            $output->writeln('<error>' . $failure->getMessage() . '</error>');

            return Command::FAILURE;
        }

        if ($applied === []) {
            $output->writeln('Already up to date.');

            return Command::SUCCESS;
        }

        foreach ($applied as $migration) {
            $output->writeln(sprintf('Applied %s_%s', $migration->version, $migration->name));
        }

        return Command::SUCCESS;
    }
}
