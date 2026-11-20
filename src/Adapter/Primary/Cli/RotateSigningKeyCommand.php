<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Port\EncryptionUnavailable;
use DateTimeInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(
    name: 'keys:rotate',
    description: 'Replace the active signing key, keeping the old one published (postgres backend).',
)]
final class RotateSigningKeyCommand extends Command
{
    public function __construct(private readonly RotateSigningKey $rotate)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $rotation = ($this->rotate)();
        } catch (EncryptionUnavailable $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $output->writeln(sprintf('Signing key %s is now active.', $rotation->active->kid()));

        $retired = $rotation->retired;
        $until = $retired?->publishedUntil();
        if ($retired !== null && $until !== null) {
            $output->writeln(sprintf(
                'Signing key %s is retired and stays in the JWKS until %s.',
                $retired->kid(),
                $until->format(DateTimeInterface::RFC3339),
            ));
        } else {
            $output->writeln('There was no active key to retire.');
        }

        return Command::SUCCESS;
    }
}
