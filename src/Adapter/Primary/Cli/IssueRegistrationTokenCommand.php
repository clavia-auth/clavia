<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Domain\Shared\InvalidValue;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Does what `POST /api/v1/initial-access-tokens` does, for a server with no dashboard yet: issue a
 * token that lets software register third-party clients (RFC 7591 §3). The token is printed once
 * and stored as its digest.
 */
#[AsCommand(
    name: 'clients:registration-token',
    description: 'Issue an initial access token for client registration and print it, once.',
)]
final class IssueRegistrationTokenCommand extends Command
{
    /**
     * @param bool $registrationOpen Whether `CLAVIA_CLIENT_REGISTRATION` lets a token register anything.
     */
    public function __construct(
        private readonly IssueInitialAccessToken $issue,
        private readonly bool $registrationOpen,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addArgument('description', InputArgument::REQUIRED, 'Who it is for: the token is never shown again.')
            ->addOption('uses', null, InputOption::VALUE_REQUIRED, 'How many clients it may register (1 to 1000).', '1')
            ->addOption(
                'expires-in',
                null,
                InputOption::VALUE_REQUIRED,
                'Seconds until it expires, from 60 to 7776000 (ninety days).',
                (string) NewInitialAccessToken::DEFAULT_LIFETIME_SECONDS,
            );
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $description */
        $description = $input->getArgument('description');
        $uses = self::integer($input->getOption('uses'));
        $lifetime = self::integer($input->getOption('expires-in'));
        if ($uses === null || $lifetime === null) {
            $output->writeln('<error>--uses and --expires-in are whole numbers.</error>');

            return Command::FAILURE;
        }

        try {
            $issued = ($this->issue)(new NewInitialAccessToken($description, $lifetime, $uses));
        } catch (InvalidValue $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        }

        $token = $issued->token;
        $output->writeln(sprintf('Issued initial access token "%s"', $token->description));
        $output->writeln("  id:         {$token->id->value}");
        $output->writeln("  token:      {$issued->secret}", OutputInterface::OUTPUT_RAW);
        $output->writeln(sprintf('  registers:  %d client%s', $token->maxUses, $token->maxUses === 1 ? '' : 's'));
        $output->writeln('  expires at: ' . $token->expiresAt->format(DATE_ATOM));
        $output->writeln('');
        $output->writeln('Stored as its digest: this is the only time it can be shown.');
        if (! $this->registrationOpen) {
            $output->writeln('');
            $output->writeln(
                '<comment>Registration is off: the token registers nothing until '
                . 'CLAVIA_CLIENT_REGISTRATION=token.</comment>',
            );
        }

        return Command::SUCCESS;
    }

    private static function integer(mixed $value): ?int
    {
        return is_string($value) && preg_match('/^[0-9]{1,10}$/D', $value) === 1 ? (int) $value : null;
    }
}
