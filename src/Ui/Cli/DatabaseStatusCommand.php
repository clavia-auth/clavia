<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Cli;

use Clavia\Application\Port\SchemaMigrationFailed;
use Clavia\Application\Port\SchemaMigrator;
use DateTimeInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia db:status` — list every migration and whether the database has it.
 *
 * Changes nothing. Exits non-zero when migrations are pending, so a deploy script or a
 * health gate can ask "is the schema current?" without parsing the output.
 */
#[AsCommand(name: 'db:status', description: 'List the database migrations and whether each is applied.')]
final class DatabaseStatusCommand extends Command
{
    /** Exit code when at least one migration is pending. */
    public const int PENDING = 2;

    public function __construct(private readonly SchemaMigrator $migrator)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $migrations = $this->migrator->status();
        } catch (SchemaMigrationFailed $failure) {
            $output->writeln('<error>' . $failure->getMessage() . '</error>');

            return Command::FAILURE;
        }

        if ($migrations === []) {
            $output->writeln('No migrations.');

            return Command::SUCCESS;
        }

        $table = new Table($output);
        $table->setHeaders(['Version', 'Name', 'Applied at (UTC)']);

        $pending = 0;
        foreach ($migrations as $migration) {
            $pending += $migration->isApplied() ? 0 : 1;
            $table->addRow([
                $migration->version,
                $migration->name,
                $migration->appliedAt?->format(DateTimeInterface::RFC3339) ?? 'pending',
            ]);
        }
        $table->render();

        if ($pending > 0) {
            $output->writeln(sprintf('%d pending. Run `clavia db:migrate`.', $pending));

            return self::PENDING;
        }

        return Command::SUCCESS;
    }
}
