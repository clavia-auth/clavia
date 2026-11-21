<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Shared\InvalidValue;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Works in every environment, unlike `seed-dev`: a machine client is the first thing a
 * real deployment needs before it can call anything else. The secret is printed once
 * and stored hashed; lose it and the fix is a new client, not a recovery.
 *
 * `--third-party` registers somebody else's machine: its id starts with `tpc_`, and it can
 * never be granted a system API.
 */
#[AsCommand(
    name: 'clients:create-m2m',
    description: 'Register a machine-to-machine client and print its id and secret, once.',
)]
final class CreateMachineClientCommand extends Command
{
    /**
     * @param string $issuer The issuer, for the token request printed at the end.
     */
    public function __construct(
        private readonly RegisterMachineClient $register,
        private readonly string $issuer,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('name', InputArgument::REQUIRED, 'A human-readable name for the client.')
            ->addOption(
                'secret',
                null,
                InputOption::VALUE_REQUIRED,
                'Use this secret (at least 32 characters) instead of a generated one. Prefer generating.',
            )
            ->addOption(
                'third-party',
                null,
                InputOption::VALUE_NONE,
                "Somebody else's machine: it can never be granted the Management API.",
            );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $name */
        $name = $input->getArgument('name');
        /** @var mixed $secret */
        $secret = $input->getOption('secret');

        try {
            $registered = ($this->register)(
                $name,
                is_string($secret) && $secret !== '' ? $secret : null,
                $input->getOption('third-party') === true ? Ownership::ThirdParty : Ownership::FirstParty,
            );
        } catch (InvalidValue $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $clientId = $registered->client->id->value;
        $output->writeln(sprintf(
            'Registered %sconfidential client "%s"',
            $registered->client->isFirstParty() ? '' : 'third-party ',
            $registered->client->name,
        ));
        $output->writeln("  client_id:     {$clientId}");
        $output->writeln("  client_secret: {$registered->secret}", OutputInterface::OUTPUT_RAW);
        if ($registered->secretGenerated) {
            $output->writeln('');
            $output->writeln('Stored hashed: this is the only time it can be shown.');
        }
        $output->writeln('');
        $output->writeln('It holds nothing until it is granted access to an API. Then request a token with:');
        $output->writeln('');
        $output->writeln("  curl -s {$this->issuer}/oauth2/token \\", OutputInterface::OUTPUT_RAW);
        $output->writeln("    -u '{$clientId}:<client_secret>' \\", OutputInterface::OUTPUT_RAW);
        $output->writeln('    -d grant_type=client_credentials \\', OutputInterface::OUTPUT_RAW);
        $output->writeln('    -d audience=<API identifier>', OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
