<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Webhooks\DeliverWebhooks;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `clavia webhooks:deliver`: sends the webhook deliveries due, then exits. Run it every minute. */
#[AsCommand(name: 'webhooks:deliver', description: 'Send the webhook deliveries that are due (run every minute).')]
final class DeliverWebhooksCommand extends Command
{
    public function __construct(private readonly DeliverWebhooks $deliver)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $run = ($this->deliver)();
        $output->writeln(sprintf(
            'Delivered %d; %d failed and will be retried; %d abandoned; %d old deliveries purged.',
            $run->succeeded,
            $run->failed,
            $run->abandoned,
            $run->purged,
        ));

        return Command::SUCCESS;
    }
}
