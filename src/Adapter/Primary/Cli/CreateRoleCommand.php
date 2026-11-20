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
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Shell-only in spirit, like `clients:grant`: this is how the first person comes to hold
 * `update:roles`, which can confer every other permission — so it should take access to
 * the deployment rather than a token. The Management API manages roles afterwards.
 */
#[AsCommand(
    name: 'roles:create',
    description: 'Create a role, or add permissions on one API to an existing one.',
)]
final class CreateRoleCommand extends Command
{
    /**
     * @param string $managementApi The Management API's identifier, the default `--audience`.
     */
    public function __construct(
        private readonly EnsureRole $ensureRole,
        private readonly string $managementApi,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('name', InputArgument::REQUIRED, 'The role, e.g. "Support".')
            ->addOption('description', null, InputOption::VALUE_REQUIRED, 'What the role is for.', '')
            ->addOption(
                'audience',
                null,
                InputOption::VALUE_REQUIRED,
                'The API to grant permissions on. Defaults to the Management API.',
            )
            ->addOption(
                'scope',
                null,
                InputOption::VALUE_REQUIRED,
                'Space-separated permissions. Defaults to every permission the API defines.',
            );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $name */
        $name = $input->getArgument('name');
        /** @var mixed $description */
        $description = $input->getOption('description');
        /** @var mixed $audience */
        $audience = $input->getOption('audience');
        $identifier = is_string($audience) && $audience !== '' ? $audience : $this->managementApi;
        /** @var mixed $scope */
        $scope = $input->getOption('scope');

        try {
            $role = ($this->ensureRole)(
                $name,
                is_string($description) ? $description : '',
                Audience::fromString($identifier),
                is_string($scope) ? ScopeSet::fromString($scope) : null,
            );
        } catch (NotFound | InvalidValue | AlreadyExists $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');
            if ($refusal instanceof NotFound && $identifier === $this->managementApi) {
                $output->writeln('Run `clavia management-api:register` first.');
            }

            return Command::FAILURE;
        }

        $output->writeln(
            sprintf("Role '%s' (%s) grants:", $role->name, $role->id->value),
            OutputInterface::OUTPUT_RAW,
        );
        $granted = array_map(
            static fn (GrantedPermission $permission): string => $permission->value->value,
            $role->permissions,
        );
        foreach ($granted === [] ? ['(nothing)'] : $granted as $value) {
            $output->writeln('  ' . $value, OutputInterface::OUTPUT_RAW);
        }
        $output->writeln('');
        $output->writeln(sprintf("Give it to somebody with `clavia roles:assign '%s' <email>`.", $role->name));

        return Command::SUCCESS;
    }
}
