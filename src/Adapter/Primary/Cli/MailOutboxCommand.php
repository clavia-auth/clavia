<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Port\MailOutbox;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The development outbox: the last messages the console mail backend "sent", newest
 * first — where to read a sign-in code or link without a mail server.
 */
#[AsCommand(name: 'mail:outbox', description: 'Show the last messages the console mail backend sent.')]
final class MailOutboxCommand extends Command
{
    private const int DEFAULT_LIMIT = 5;

    public function __construct(private readonly MailOutbox $outbox)
    {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this->addOption(
            'limit',
            'l',
            InputOption::VALUE_REQUIRED,
            'How many messages to show (at most 50).',
            (string) self::DEFAULT_LIMIT,
        );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $limit = $input->getOption('limit');
        if (! is_string($limit) || ! ctype_digit($limit) || (int) $limit < 1) {
            $output->writeln('<error>--limit is a positive whole number.</error>');

            return Command::INVALID;
        }

        $mails = $this->outbox->recent(max(1, (int) $limit));
        if ($mails === []) {
            $output->writeln(
                'The outbox is empty. Only CLAVIA_EMAIL_BACKEND=console keeps one; smtp delivers for real.',
            );

            return Command::SUCCESS;
        }

        foreach ($mails as $index => $mail) {
            if ($index > 0) {
                $output->writeln(str_repeat('─', 60));
            }
            // What the messages say is data, not console markup.
            $output->writeln('<info>To:</info>      ' . OutputFormatter::escape($mail->to));
            $output->writeln('<info>Subject:</info> ' . OutputFormatter::escape($mail->subject));
            $output->writeln('');
            $output->writeln(OutputFormatter::escape($mail->text));
        }

        return Command::SUCCESS;
    }
}
