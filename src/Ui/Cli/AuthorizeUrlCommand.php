<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Cli;

use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia authorize-url` — print a ready-to-open authorization URL with a fresh PKCE
 * pair, and the `curl` command that redeems the code it produces.
 */
#[AsCommand(name: 'authorize-url', description: 'Print an authorization URL with a fresh PKCE pair.')]
final class AuthorizeUrlCommand extends Command
{
    /**
     * @param string      $issuer            The origin the URL points at.
     * @param string|null $devAutologinEmail The development auto-login account, when the shortcut is on.
     */
    public function __construct(
        private readonly BuildAuthorizationUrl $build,
        private readonly string $issuer,
        private readonly ?string $devAutologinEmail,
    ) {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this
            ->addOption(
                'client-id',
                null,
                InputOption::VALUE_REQUIRED,
                'Client to authorize as. Defaults to the client `seed-dev` registers.',
            )
            ->addOption(
                'redirect-uri',
                null,
                InputOption::VALUE_REQUIRED,
                'Must match a registered redirect URI.',
                'http://localhost:3000/callback',
            )
            ->addOption('scope', null, InputOption::VALUE_REQUIRED, 'Defaults to every scope the server supports.');
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $clientId = $this->option($input, 'client-id');
        $scope = $this->option($input, 'scope');
        $redirectUri = $this->option($input, 'redirect-uri') ?? 'http://localhost:3000/callback';

        try {
            $url = ($this->build)(
                $clientId === null ? null : ClientId::fromString($clientId),
                $redirectUri,
                $scope === null ? null : ScopeSet::fromString($scope),
            );
        } catch (InvalidValue $invalid) {
            $output->writeln('<error>' . $invalid->getMessage() . '</error>');

            return Command::FAILURE;
        }

        if ($url === null) {
            $output->writeln(
                '<error>No client id given, and no seeded development client found. '
                . 'Run `clavia seed-dev` first, or pass --client-id.</error>',
            );

            return Command::FAILURE;
        }

        $raw = OutputInterface::OUTPUT_RAW;

        if ($this->devAutologinEmail !== null) {
            $output->writeln([
                '',
                "  NOTE: CLAVIA_DEV_AUTOLOGIN_EMAIL is set to '{$this->devAutologinEmail}',",
                '        so /oauth2/authorize will issue a code immediately and you will never',
                '        see the login page. Comment it out in .env to exercise the redirect.',
            ], $raw);
        }

        $query = http_build_query($url->parameters, '', '&', PHP_QUERY_RFC3986);

        $output->writeln([
            '',
            '1. Open this — you should be redirected to the sign-in page:',
            '',
            "   {$this->issuer}/oauth2/authorize?{$query}",
            '',
            '2. Sign in. You land back on /oauth2/authorize, which redirects to',
            "   {$url->redirectUri}?code=…  — unless something listens there, the browser shows a",
            '   connection error. Copy the code out of the address bar.',
            '',
            '3. Redeem it:',
            '',
            "   curl -s {$this->issuer}/oauth2/token \\",
            '     -d grant_type=authorization_code \\',
            "     -d client_id={$url->clientId->value} \\",
            "     -d redirect_uri={$url->redirectUri} \\",
            "     -d code_verifier={$url->verifier->value} \\",
            '     -d code=<CODE FROM STEP 2>',
            '',
        ], $raw);

        return Command::SUCCESS;
    }

    private function option(InputInterface $input, string $name): ?string
    {
        /** @var mixed $value */
        $value = $input->getOption($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
