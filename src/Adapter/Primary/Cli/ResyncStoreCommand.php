<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Cli;

use Clavia\Application\Authorization\Feed\FineGrainedAuthorizationOff;
use Clavia\Application\Authorization\Feed\ResyncStore;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngineFailed;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `clavia fga:resync <api>`: works out every role's members in an API's store from Clavia and writes
 * the difference (docs/design/fine-grained-authorization.md §5.4), the repair when they have drifted.
 */
#[AsCommand(
    name: 'fga:resync',
    description: "Bring an API's store in the decision engine back into step with Clavia's roles.",
)]
final class ResyncStoreCommand extends Command
{
    public function __construct(private readonly ResyncStore $resync)
    {
        parent::__construct();
    }

    #[\Override]
    protected function configure(): void
    {
        $this->addArgument('api', InputArgument::REQUIRED, "The API's id (rs_…) or its identifier.");
    }

    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        /** @var string $api */
        $api = $input->getArgument('api');

        try {
            $done = ($this->resync)($api);
        } catch (NotFound | FineGrainedAuthorizationOff $refusal) {
            $output->writeln('<error>' . $refusal->getMessage() . '</error>');

            return Command::FAILURE;
        } catch (DecisionEngineFailed) {
            // The adapter logged why; the store is as far as it got, and running it again finishes it.
            $output->writeln('<error>The decision engine did not answer, or refused a write. Run it again.</error>');

            return Command::FAILURE;
        }
        $output->writeln(sprintf(
            'In step: %d role membership(s) written, %d deleted.',
            $done->written,
            $done->deleted,
        ));

        return Command::SUCCESS;
    }
}
