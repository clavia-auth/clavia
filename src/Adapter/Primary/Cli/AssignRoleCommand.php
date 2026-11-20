<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Domain\Rbac\Role;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The bootstrap step of a new deployment: until somebody holds a role with `read:users`
 * on the Management API, the dashboard has nothing to show them.
 */
#[AsCommand(name: 'roles:assign', description: 'Give a user a role.')]
final class AssignRoleCommand extends Command
{
    public function __construct(private readonly AssignRole $assign)
    {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('role', InputArgument::REQUIRED, 'The role, by name.')
            ->addArgument('email', InputArgument::REQUIRED, 'The user, by the address they signed up with.');
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $role */
        $role = $input->getArgument('role');
        /** @var string $email */
        $email = $input->getArgument('email');

        try {
            $held = ($this->assign)($role, $email);
        } catch (NotFound $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $names = array_map(static fn (Role $one): string => $one->name, $held);
        $output->writeln(sprintf('%s now holds: %s', $email, implode(', ', $names)), OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
