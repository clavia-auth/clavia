<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\Provisioning\RegisterAuthorizationApi;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * A bootstrap step that has to live outside HTTP: until the Management API is
 * registered no token can name it as its audience, and until one can, nothing under
 * `/api/v1` answers. Safe to run again after every upgrade.
 *
 * With fine-grained authorization on, it registers the Authorization API too: the system API an
 * API's own client is granted on to ask for decisions.
 */
#[AsCommand(
    name: 'management-api:register',
    description: 'Register the Management API (or bring its permissions up to date) so tokens can be issued for it.',
)]
final class RegisterManagementApiCommand extends Command
{
    public function __construct(
        private readonly RegisterManagementApi $register,
        private readonly ?RegisterAuthorizationApi $registerAuthorizationApi = null,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $api = ($this->register)();

        $output->writeln('Management API registered as ' . $api->identifier->value, OutputInterface::OUTPUT_RAW);
        $output->writeln('  scopes: ' . $api->permissionScopes()->toString(), OutputInterface::OUTPUT_RAW);
        if ($this->registerAuthorizationApi !== null) {
            $authorization = ($this->registerAuthorizationApi)();
            $output->writeln(
                'Authorization API registered as ' . $authorization->identifier->value,
                OutputInterface::OUTPUT_RAW,
            );
            $output->writeln(
                '  scopes: ' . $authorization->permissionScopes()->toString(),
                OutputInterface::OUTPUT_RAW,
            );
        }
        $output->writeln('');
        $output->writeln('Grant a machine client access to it with `clavia clients:grant <client_id>`.');

        return Command::SUCCESS;
    }
}
