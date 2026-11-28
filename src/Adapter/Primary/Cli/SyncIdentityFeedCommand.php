<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Authorization\Feed\SyncIdentityFeed;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia fga:sync`: sends what the identity feed still owes the decision engine, then exits. Run it
 * every minute (docs/design/fine-grained-authorization.md §5.4): most of it is sent after the response
 * that queued it, and this picks up what failed.
 */
#[AsCommand(
    name: 'fga:sync',
    description: 'Send the identity changes the decision engine has not taken yet (run every minute).',
)]
final class SyncIdentityFeedCommand extends Command
{
    public function __construct(private readonly SyncIdentityFeed $sync)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $run = ($this->sync)();
        if (! $run->available) {
            $output->writeln('Fine-grained authorization is off (CLAVIA_FGA_URL is unset): nothing sent.');

            return Command::SUCCESS;
        }
        $output->writeln(sprintf(
            'Sent %d identity change(s); %d could not be sent and will be retried; %d waiting.',
            $run->sent,
            $run->failed,
            $run->pending,
        ));
        if ($run->failed > 0) {
            $errors = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
            $errors->writeln(sprintf(
                '<comment>Warning: the decision engine did not take %d identity change(s); '
                . 'they are retried with a backoff. Check that OpenFGA is reachable.</comment>',
                $run->failed,
            ));
        }

        return Command::SUCCESS;
    }
}
