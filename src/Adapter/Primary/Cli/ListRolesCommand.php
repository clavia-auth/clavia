<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\Roles\ReadRoles;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'roles:list', description: 'List the roles and how many permissions each grants.')]
final class ListRolesCommand extends Command
{
    public function __construct(private readonly ReadRoles $read)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $roles = $this->read->all();
        if ($roles === []) {
            $output->writeln('No roles. Create one with `clavia roles:create`.');

            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($roles as $role) {
            $rows[] = [$role->name, $role->id->value, (string) count($role->permissions), $role->description];
        }

        new Table($output)
            ->setHeaders(['name', 'id', 'permissions', 'description'])
            ->setRows($rows)
            ->render();

        return Command::SUCCESS;
    }
}
