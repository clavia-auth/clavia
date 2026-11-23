<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Clients\Registration\PurgeUnusedRegistrations;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Deletes the self-registered clients never issued a token past
 * `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME`. Meant for a daily scheduler, like `audit:purge`.
 */
#[AsCommand(
    name: 'clients:purge-unused',
    description: 'Delete the self-registered clients never issued a token, past their lifetime.',
)]
final class PurgeUnusedClientsCommand extends Command
{
    public function __construct(private readonly PurgeUnusedRegistrations $purge)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $deleted = ($this->purge)();
        $output->writeln($deleted === 0
            ? 'No self-registered client is unused past its lifetime.'
            : sprintf('Deleted %d unused self-registered client%s.', $deleted, $deleted === 1 ? '' : 's'));

        return Command::SUCCESS;
    }
}
