<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Domain\Shared\InvalidValue;
use LogicException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia seed-dev` — seed a development user and a public PKCE client.
 *
 * Development only, and safe to run again: it creates what is missing and reports what
 * was already there.
 */
#[AsCommand(name: 'seed-dev', description: 'Seed a development user and a public PKCE client.')]
final class SeedDevelopmentDataCommand extends Command
{
    /**
     * @param string $rootDomain The deployment's domain, for the default email address.
     * @param string $issuer     The issuer, for the sign-in URL printed at the end.
     */
    public function __construct(
        private readonly SeedDevelopmentData $seed,
        private readonly SeedManagementAccess $seedManagementAccess,
        private readonly string $rootDomain,
        private readonly string $issuer,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addOption(
                'email',
                null,
                InputOption::VALUE_REQUIRED,
                'Email of the development user. Defaults to dev@{CLAVIA_ROOT_DOMAIN}.',
            )
            ->addOption(
                'password',
                null,
                InputOption::VALUE_REQUIRED,
                'Password for the development user.',
                'devpassword',
            )
            ->addOption(
                'redirect-uri',
                null,
                InputOption::VALUE_REQUIRED,
                'Redirect URI to register.',
                'http://localhost:3000/callback',
            );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $email = $this->option($input, 'email') ?? 'dev@' . $this->rootDomain;
        $password = $this->option($input, 'password') ?? 'devpassword';
        $redirectUri = $this->option($input, 'redirect-uri') ?? 'http://localhost:3000/callback';

        try {
            $seeded = ($this->seed)($email, $password, $redirectUri);
            $management = ($this->seedManagementAccess)();
        } catch (LogicException | InvalidValue $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $output->writeln($seeded->userCreated ? "Created user {$email}" : "User {$email} already exists");
        $output->writeln(
            $seeded->clientCreated
                ? "Created public client {$seeded->clientId->value}"
                : "Client {$seeded->clientId->value} already exists",
        );
        $output->writeln(
            $seeded->signingKeyCreated
                ? "Created signing key {$seeded->signingKeyId}"
                : "Signing key {$seeded->signingKeyId} is already active",
        );
        $output->writeln(
            "Registered the Management API as {$management->managementApi->value}",
            OutputInterface::OUTPUT_RAW,
        );
        $output->writeln(sprintf(
            '%s machine client %s, granted every management scope',
            $management->clientCreated ? 'Created' : 'Kept',
            $management->clientId->value,
        ));
        $output->writeln('');
        $output->writeln("Seeded. Sign in at {$this->issuer}/auth/login as {$email} / {$password}");
        $output->writeln('Run `clavia authorize-url` to get a link that exercises the whole flow.');
        $output->writeln('Call the Management API with a token from:');
        $output->writeln('');
        $output->writeln("  curl -s {$this->issuer}/oauth2/token \\", OutputInterface::OUTPUT_RAW);
        $output->writeln(
            sprintf("    -u '%s:%s' \\", $management->clientId->value, SeedManagementAccess::CLIENT_SECRET),
            OutputInterface::OUTPUT_RAW,
        );
        $output->writeln('    -d grant_type=client_credentials \\', OutputInterface::OUTPUT_RAW);
        $output->writeln("    -d audience={$management->managementApi->value}", OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }

    private function option(InputInterface $input, string $name): ?string
    {
        /** @var mixed $value */
        $value = $input->getOption($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
