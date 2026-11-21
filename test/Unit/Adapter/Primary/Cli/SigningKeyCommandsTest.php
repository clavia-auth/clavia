<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\GenerateSigningKeyCommand;
use Clavia\Adapter\Primary\Cli\ListSigningKeysCommand;
use Clavia\Adapter\Primary\Cli\RotateSigningKeyCommand;
use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class SigningKeyCommandsTest extends TestCase
{
    private FrozenClock $clock;
    private InMemorySigningKeys $keys;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->keys = new InMemorySigningKeys($this->clock);
    }

    public function testGenerateCreatesTheFirstKeyAndSaysWhichOne(): void
    {
        $tester = $this->generate();

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame(
            "Created signing key {$this->keys->activeKey()->kid} (RS256). It signs from now on.\n",
            $tester->getDisplay(true),
        );
    }

    public function testGenerateRefusesToReplaceAnActiveKey(): void
    {
        $this->generate()->execute([]);
        $tester = $this->generate();

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString('Run `clavia keys:rotate`', $tester->getDisplay(true));
        self::assertCount(1, $this->keys->all());
    }

    public function testRotateSaysWhichKeySignsAndUntilWhenTheOldOneIsPublished(): void
    {
        $this->generate()->execute([]);
        $old = $this->keys->activeKey()->kid;
        $tester = $this->rotate();

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame(
            "Signing key {$this->keys->activeKey()->kid} is now active.\n"
            . "Signing key {$old} is retired and stays in the JWKS until 2026-01-15T11:00:00+00:00.\n",
            $tester->getDisplay(true),
        );
    }

    public function testRotateWithNothingToRetireSaysSo(): void
    {
        $tester = $this->rotate();

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('There was no active key to retire.', $tester->getDisplay(true));
    }

    public function testListShowsEachKeyAndWhetherItIsPublished(): void
    {
        $this->generate()->execute([]);
        $first = $this->keys->activeKey()->kid;
        $this->rotate()->execute([]);
        $this->clock->advance(3600);

        $tester = new CommandTester(new ListSigningKeysCommand(new ListSigningKeys($this->keys, $this->clock)));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        $display = $tester->getDisplay(true);
        self::assertStringContainsString($this->keys->activeKey()->kid, $display);
        self::assertMatchesRegularExpression(
            '/' . preg_quote($first, '/') . '.*retired.*no, since 2026-01-15T11:00:00/',
            $display,
        );
        self::assertMatchesRegularExpression('/active .*\| yes/', $display);
    }

    public function testListWithNoKeySaysHowToCreateOne(): void
    {
        $tester = new CommandTester(new ListSigningKeysCommand(new ListSigningKeys($this->keys, $this->clock)));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('Run `clavia keys:generate`', $tester->getDisplay(true));
    }

    private function generate(): CommandTester
    {
        return new CommandTester(new GenerateSigningKeyCommand(
            new GenerateSigningKey(
                $this->keys,
                new InMemoryTransactionManager(),
                $this->clock,
                SigningAlgorithm::RS256,
                new InMemoryDomainEvents(),
            ),
        ));
    }

    private function rotate(): CommandTester
    {
        return new CommandTester(new RotateSigningKeyCommand(new RotateSigningKey(
            $this->keys,
            new InMemoryTransactionManager(),
            $this->clock,
            SigningAlgorithm::RS256,
            3600,
            new InMemoryDomainEvents(),
        )));
    }
}
