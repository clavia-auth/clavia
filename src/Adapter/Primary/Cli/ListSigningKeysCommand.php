<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Oidc\Keys\ListSigningKeys;
use DateTimeInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'keys:list', description: 'List the signing keys and whether each is still published.')]
final class ListSigningKeysCommand extends Command
{
    public function __construct(private readonly ListSigningKeys $list)
    {
        parent::__construct();
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $listed = ($this->list)();
        if ($listed === []) {
            $output->writeln('No signing key. Run `clavia keys:generate` to create one.');

            return Command::SUCCESS;
        }

        $rows = [];
        foreach ($listed as $entry) {
            $key = $entry->key;
            $until = $key->publishedUntil();
            $rows[] = [
                $key->kid(),
                $key->algorithm()->value,
                $key->status()->value,
                $key->createdAt->format(DateTimeInterface::RFC3339),
                match (true) {
                    $until === null => 'yes',
                    $entry->published => 'until ' . $until->format(DateTimeInterface::RFC3339),
                    default => 'no, since ' . $until->format(DateTimeInterface::RFC3339),
                },
            ];
        }

        new Table($output)
            ->setHeaders(['kid', 'algorithm', 'status', 'created', 'published'])
            ->setRows($rows)
            ->render();

        return Command::SUCCESS;
    }
}
