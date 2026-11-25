<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Connection\Saml\GenerateServiceProviderKeys;
use Clavia\Application\Connection\Saml\ServiceProviderKeysExist;
use Clavia\Application\Port\EncryptionUnavailable;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `clavia saml-keys:generate`: the SAML service provider's first signing and encryption keys. */
#[AsCommand(
    name: 'saml-keys:generate',
    description: 'Make the SAML service provider\'s first signing and encryption keys (postgres backend).',
)]
final class GenerateServiceProviderKeysCommand extends Command
{
    public function __construct(private readonly GenerateServiceProviderKeys $generate)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $keys = ($this->generate)();
        } catch (ServiceProviderKeysExist | EncryptionUnavailable $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }
        foreach ($keys->published()->keys as $key) {
            $output->writeln(sprintf(
                '%s key %s (certificate SHA-256 %s).',
                ucfirst($key->usage->value),
                $key->kid,
                $key->fingerprint(),
            ));
        }

        return Command::SUCCESS;
    }
}
