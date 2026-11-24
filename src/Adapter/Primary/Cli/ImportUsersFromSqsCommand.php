<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\Sqs\QueueMessage;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessages;
use Clavia\Adapter\Primary\Cli\Sqs\QueueMessagesFactory;
use Clavia\Application\Management\Users\Import\ImportRefusal;
use Clavia\Application\Management\Users\Import\UserImport;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

/**
 * Listens to an AWS SQS queue and imports one account per message, through the {@see UserImport}
 * port: the rules of an import job's line, the same refusals (#108).
 *
 * A message's body is one account's JSON object; its `connection` attribute names the pool (the
 * default pool when absent). An account made, or refused for good (the same message would be
 * refused again), deletes the message; the refusal is logged by message id and code, never the body.
 * Anything unexpected (the database down) leaves the message, which comes back after its visibility
 * timeout and reaches the dead-letter queue after the redrive policy's count. Delivery is at least
 * once: a message imported twice is refused the second time as `already_exists`, and deleted.
 *
 * It runs until stopped. With the `pcntl` extension, SIGTERM or SIGINT stops it after the message in
 * hand; `--max-messages` and `--idle-exit` end a batch run.
 */
#[AsCommand(name: 'users:import-sqs', description: 'Import accounts from an AWS SQS queue, one per message.')]
final class ImportUsersFromSqsCommand extends Command
{
    private const int LONG_POLL_SECONDS = 20;

    /** POSIX's numbers, the same everywhere; pcntl's constants exist only with pcntl loaded. */
    private const int SIGINT = 2;
    private const int SIGTERM = 15;

    private bool $stopping = false;

    public function __construct(
        private readonly QueueMessagesFactory $queues,
        private readonly UserImport $imports,
        private readonly LoggerInterface $logger,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('queue-url', InputArgument::REQUIRED, 'https://sqs.<region>.amazonaws.com/<account>/<queue>')
            ->addOption('max-messages', null, InputOption::VALUE_REQUIRED, 'Stop after this many messages.')
            ->addOption('idle-exit', null, InputOption::VALUE_NONE, 'Stop once a long poll finds the queue empty.');
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $url */
        $url = $input->getArgument('queue-url');
        /** @var mixed $max */
        $max = $input->getOption('max-messages');
        if ($max !== null && (! is_string($max) || preg_match('/^[1-9][0-9]{0,8}$/D', $max) !== 1)) {
            $output->writeln('<error>--max-messages is a positive whole number.</error>');

            return Command::FAILURE;
        }
        $limit = $max === null ? null : (int) $max;

        try {
            $queue = $this->queues->open($url);
        } catch (InvalidArgumentException $refused) {
            $output->writeln('<error>' . $refused->getMessage() . '</error>');

            return Command::FAILURE;
        }
        $this->listenForStop();

        $counts = ['imported' => 0, 'refused' => 0, 'left' => 0];
        while (! $this->isStopping() && ($limit === null || array_sum($counts) < $limit)) {
            $want = $limit === null ? 10 : max(1, min(10, $limit - array_sum($counts)));
            $messages = $queue->receive($want, self::LONG_POLL_SECONDS);
            if ($messages === []) {
                if ($input->getOption('idle-exit') === true) {
                    break;
                }
                continue;
            }
            foreach ($messages as $message) {
                if ($this->isStopping()) {
                    // Not taken: it comes back to the queue after its visibility timeout.
                    break;
                }
                ++$counts[$this->handle($queue, $message)];
            }
        }

        $output->writeln(sprintf(
            'Imported %d, refused %d, left %d for a retry.',
            $counts['imported'],
            $counts['refused'],
            $counts['left'],
        ));

        return Command::SUCCESS;
    }

    /** @return 'imported'|'refused'|'left' */
    private function handle(QueueMessages $queue, QueueMessage $message): string
    {
        try {
            $pool = $message->connection === null
                ? ConnectionName::defaultPool()
                : ConnectionName::fromString($message->connection);
        } catch (InvalidValue) {
            $pool = null;
        }

        try {
            $outcome = $pool === null
                ? new ImportRefusal('invalid_connection', 'The connection attribute is not a connection name.')
                : $this->imports->import($message->body, $pool);
        } catch (Throwable $failure) {
            // Not deleted: it comes back, and reaches the dead-letter queue if it keeps failing.
            $this->logger->error('An SQS message could not be imported: {exception}', [
                'message_id' => $message->id,
                'exception' => $failure::class,
            ]);

            return 'left';
        }
        $queue->delete($message);

        if ($outcome instanceof ImportRefusal) {
            $this->logger->warning('An SQS message was refused: {error}', [
                'message_id' => $message->id,
                'error' => $outcome->error,
            ]);

            return 'refused';
        }
        $this->logger->info('An account was imported from SQS.', [
            'message_id' => $message->id,
            'user_id' => $outcome->id->value,
        ]);

        return 'imported';
    }

    /** Read through a method: the flag changes in a signal handler, between two reads. */
    private function isStopping(): bool
    {
        return $this->stopping;
    }

    /** With `pcntl`, a stop signal ends the loop after the message in hand rather than in its middle. */
    private function listenForStop(): void
    {
        if (! function_exists('pcntl_async_signals') || ! function_exists('pcntl_signal')) {
            return;
        }
        pcntl_async_signals(true);
        foreach ([self::SIGTERM, self::SIGINT] as $signal) {
            pcntl_signal($signal, function (): void {
                $this->stopping = true;
            });
        }
    }
}
