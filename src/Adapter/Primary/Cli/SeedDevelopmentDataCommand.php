<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Development\SeedDashboardClient;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Shared\InvalidValue;
use LogicException;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia seed-dev` — seed a development user holding the Administrator role, a public
 * PKCE client, the Management API with a machine client, and the dashboard's client and
 * build configuration.
 *
 * Development only, and safe to run again: it creates what is missing and reports what
 * was already there.
 */
#[AsCommand(name: 'seed-dev', description: 'Seed development users, clients and the dashboard.')]
final class SeedDevelopmentDataCommand extends Command
{
    /**
     * @param string      $rootDomain       The deployment's domain, for the default email address.
     * @param string      $issuer           The issuer, for the sign-in URL printed at the end.
     * @param string      $managementHost   `management.{domain}`, where the dashboard is served.
     * @param string|null $dashboardEnvFile Where the dashboard reads its build configuration
     *                                      (`frontend/.env.local`); written only when its directory exists.
     */
    public function __construct(
        private readonly SeedDevelopmentData $seed,
        private readonly SeedManagementAccess $seedManagementAccess,
        private readonly SeedDashboardClient $seedDashboard,
        private readonly string $rootDomain,
        private readonly string $issuer,
        private readonly string $managementHost,
        private readonly ?string $dashboardEnvFile,
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
            $management = ($this->seedManagementAccess)($email);
            $dashboard = ($this->seedDashboard)($this->managementHost);
        } catch (LogicException | InvalidValue | NotFound $refusal) {
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
        $output->writeln(sprintf("Gave %s the '%s' role", $email, SeedManagementAccess::ADMINISTRATOR_ROLE));
        $output->writeln(sprintf(
            '%s dashboard client %s',
            $dashboard->created ? 'Created' : 'Kept',
            $dashboard->clientId->value,
        ));
        if ($this->writeDashboardConfiguration($dashboard->clientId->value, $management->managementApi->value)) {
            $output->writeln("Wrote the dashboard's configuration to {$this->dashboardEnvFile}");
        }
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

    /**
     * Write what the dashboard is built with (Vite reads `VITE_*` from `.env.local`).
     * Nothing in it is a secret: the dashboard is a public client.
     */
    private function writeDashboardConfiguration(string $clientId, string $audience): bool
    {
        if ($this->dashboardEnvFile === null || ! is_dir(dirname($this->dashboardEnvFile))) {
            return false;
        }

        $written = file_put_contents($this->dashboardEnvFile, implode("\n", [
            '# Written by `clavia seed-dev`. The dashboard reads these at build time.',
            'VITE_CLAVIA_ISSUER=' . $this->issuer,
            'VITE_CLAVIA_CLIENT_ID=' . $clientId,
            'VITE_CLAVIA_AUDIENCE=' . $audience,
            'VITE_CLAVIA_MANAGEMENT_HOST=' . $this->managementHost,
            '',
        ]));

        return $written !== false;
    }

    private function option(InputInterface $input, string $name): ?string
    {
        /** @var mixed $value */
        $value = $input->getOption($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
