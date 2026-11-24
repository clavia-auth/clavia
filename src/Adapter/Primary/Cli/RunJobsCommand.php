<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\Users\Jobs\RunUserJobs;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs the queued bulk jobs on the users (imports), then exits. Meant for a scheduler, every
 * minute: `* * * * * bin/clavia jobs:run`. Two runs at once never share a job.
 */
#[AsCommand(name: 'jobs:run', description: 'Run the queued bulk jobs on the users, then exit.')]
final class RunJobsCommand extends Command
{
    public function __construct(private readonly RunUserJobs $run)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $run = ($this->run)();
        $output->writeln(sprintf(
            'Ran %d job%s; %d stalled job%s failed; %d finished job%s purged.',
            $run->completed,
            $run->completed === 1 ? '' : 's',
            $run->stalled,
            $run->stalled === 1 ? '' : 's',
            $run->purged,
            $run->purged === 1 ? '' : 's',
        ));

        return Command::SUCCESS;
    }
}
