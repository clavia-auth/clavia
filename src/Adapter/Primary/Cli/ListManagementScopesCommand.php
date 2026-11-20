<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\ManagementPermission;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The scopes the Management API defines, one per line with what it allows — the
 * values `clients:grant --scope` takes. Read from the code, not the database: it works
 * before `management-api:register` has run.
 */
#[AsCommand(name: 'management-api:scopes', description: 'List the scopes the Management API defines.')]
final class ListManagementScopesCommand extends Command
{
    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $width = max(array_map(
            static fn (ManagementPermission $permission): int => strlen($permission->value),
            ManagementPermission::cases(),
        ));
        foreach (ManagementPermission::cases() as $permission) {
            $output->writeln(
                sprintf('%-' . $width . 's  %s', $permission->value, $permission->description()),
                OutputInterface::OUTPUT_RAW,
            );
        }

        return Command::SUCCESS;
    }
}
