<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\SigningKeyAlreadyActive;
use Clavia\Application\Port\EncryptionUnavailable;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'keys:generate', description: 'Create the first signing key (postgres backend).')]
final class GenerateSigningKeyCommand extends Command
{
    public function __construct(private readonly GenerateSigningKey $generate)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $key = ($this->generate)();
        } catch (SigningKeyAlreadyActive | EncryptionUnavailable $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $output->writeln(sprintf(
            'Created signing key %s (%s). It signs from now on.',
            $key->kid(),
            $key->algorithm()->value,
        ));

        return Command::SUCCESS;
    }
}
