<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Connection\Saml\ListServiceProviderKeys;
use DateTimeInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `clavia saml-keys:list`: kid, usage, status, certificate fingerprint and expiry; never key material. */
#[AsCommand(
    name: 'saml-keys:list',
    description: 'List the SAML service provider keys and their place in the rotation.',
)]
final class ListServiceProviderKeysCommand extends Command
{
    public function __construct(private readonly ListServiceProviderKeys $list)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $keys = ($this->list)();
        if ($keys->isEmpty()) {
            $output->writeln('No SAML service provider key. Run `clavia saml-keys:generate` to make them.');

            return Command::SUCCESS;
        }
        $rows = [];
        foreach ($keys->keys as $key) {
            $rows[] = [
                $key->kid,
                $key->usage->value,
                $key->status->value,
                $key->fingerprint(),
                $key->validUntil->format(DateTimeInterface::RFC3339),
            ];
        }
        new Table($output)
            ->setHeaders(['kid', 'usage', 'status', 'certificate SHA-256', 'valid until'])
            ->setRows($rows)
            ->render();

        return Command::SUCCESS;
    }
}
