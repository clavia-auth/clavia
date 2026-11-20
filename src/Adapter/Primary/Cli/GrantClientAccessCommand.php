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
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Domain\Client\ClientId;
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
 * Deliberately shell-only, with no `/api/v1` equivalent: an endpoint that wrote client
 * grants would let a token widen its own access. Replaces the client's grant on that
 * API — it states what the client should hold, so fewer scopes take the others away.
 */
#[AsCommand(
    name: 'clients:grant',
    description: 'Set the scopes a machine client may request from an API, as itself.',
)]
final class GrantClientAccessCommand extends Command
{
    /**
     * @param string $managementApi The Management API's identifier, the default `--audience`.
     * @param string $issuer        The issuer, for the token request printed at the end.
     */
    public function __construct(
        private readonly GrantClientAccess $grant,
        private readonly string $managementApi,
        private readonly string $issuer,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('client_id', InputArgument::REQUIRED, 'The client to grant access to.')
            ->addOption(
                'audience',
                null,
                InputOption::VALUE_REQUIRED,
                'The API identifier. Defaults to the Management API.',
            )
            ->addOption(
                'scope',
                null,
                InputOption::VALUE_REQUIRED,
                'Space-separated scopes. Defaults to every permission the API defines; "" grants none.',
            );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $clientId */
        $clientId = $input->getArgument('client_id');
        /** @var mixed $audience */
        $audience = $input->getOption('audience');
        $identifier = is_string($audience) && $audience !== '' ? $audience : $this->managementApi;
        /** @var mixed $scope */
        $scope = $input->getOption('scope');

        try {
            $grant = ($this->grant)(
                ClientId::fromString($clientId),
                Audience::fromString($identifier),
                is_string($scope) ? ScopeSet::fromString($scope) : null,
            );
        } catch (NotFound | InvalidValue $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');
            if ($refusal instanceof NotFound && $identifier === $this->managementApi) {
                $output->writeln('If the API is the one missing, run `clavia management-api:register` first.');
            }

            return Command::FAILURE;
        }

        $output->writeln(sprintf('Granted %s on %s:', $clientId, $identifier), OutputInterface::OUTPUT_RAW);
        $output->writeln('  ' . ($grant->scopes->isEmpty() ? '(no scopes)' : $grant->scopes->toString()));
        $output->writeln('');
        $output->writeln('Request a token for it with:');
        $output->writeln('');
        $output->writeln("  curl -s {$this->issuer}/oauth2/token \\", OutputInterface::OUTPUT_RAW);
        $output->writeln("    -u '{$clientId}:<client_secret>' \\", OutputInterface::OUTPUT_RAW);
        $output->writeln('    -d grant_type=client_credentials \\', OutputInterface::OUTPUT_RAW);
        $output->writeln("    -d audience={$identifier}", OutputInterface::OUTPUT_RAW);

        return Command::SUCCESS;
    }
}
