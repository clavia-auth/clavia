<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Clavia\Application\Connection\Saml\RotationStep;
use Clavia\Application\Port\EncryptionUnavailable;
use DateTimeInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `clavia saml-keys:rotate`: one step of the rollover, next then current then retired. */
#[AsCommand(
    name: 'saml-keys:rotate',
    description: 'Publish the next SAML service provider keys, or promote them once published long enough.',
)]
final class RotateServiceProviderKeysCommand extends Command
{
    public function __construct(private readonly RotateServiceProviderKeys $rotate)
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
        $when = $rotation->promotesAt?->format(DateTimeInterface::RFC3339) ?? '';
        $output->writeln(match ($rotation->step) {
            RotationStep::Generated => 'There were no keys: the first pair is current.',
            RotationStep::Introduced => 'A next pair is published in the metadata; rotate again after ' . $when
                . ' to promote it.',
            RotationStep::Waiting => 'The next pair is published until ' . $when . ': nothing to do before then.',
            RotationStep::Promoted => 'The next pair is current; the one it replaces is retired, its encryption'
                . ' key still decrypting.',
        });
        foreach ($rotation->deleted as $kid) {
            $output->writeln(sprintf('Retired key %s deleted.', $kid));
        }

        return Command::SUCCESS;
    }
}
