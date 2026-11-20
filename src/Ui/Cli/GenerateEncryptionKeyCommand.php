<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Cli;

use Clavia\Application\Secrets\GenerateEncryptionKey;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia secrets:generate-key` — print a key for `CLAVIA_SECRET_ENCRYPTION_KEY`.
 *
 * It encrypts the secrets this server has to be able to *read*, rather than merely
 * compare — the postgres backend's private signing key, TOTP seeds. Without it those
 * features refuse to work; there is deliberately no fallback to storing them in the
 * clear.
 *
 * Changing the key makes everything encrypted under the old one unreadable. Rotate it
 * only on purpose.
 */
#[AsCommand(name: 'secrets:generate-key', description: 'Print a fresh key for CLAVIA_SECRET_ENCRYPTION_KEY.')]
final class GenerateEncryptionKeyCommand extends Command
{
    public function __construct(private readonly GenerateEncryptionKey $generate)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // A line ready to paste into .env. Nothing is stored: the operator keeps the key.
        $output->writeln('CLAVIA_SECRET_ENCRYPTION_KEY=' . ($this->generate)(), OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
