<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Audit\PurgeAuditEvents;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Trims the audit trail to `CLAVIA_AUDIT_RETENTION_DAYS`. Meant for a daily scheduler; the
 * only way an audit event is ever removed.
 */
#[AsCommand(name: 'audit:purge', description: 'Remove the audit events older than CLAVIA_AUDIT_RETENTION_DAYS.')]
final class PurgeAuditEventsCommand extends Command
{
    public function __construct(private readonly PurgeAuditEvents $purge)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $removed = ($this->purge)();
        $output->writeln($removed === 0
            ? 'No audit event is past retention.'
            : sprintf('Removed %d audit event%s past retention.', $removed, $removed === 1 ? '' : 's'));

        return Command::SUCCESS;
    }
}
