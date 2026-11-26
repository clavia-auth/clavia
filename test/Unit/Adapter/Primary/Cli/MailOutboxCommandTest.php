<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\MailOutboxCommand;
use Clavia\Application\Port\RenderedMail;
use ClaviaTest\Support\Fake\InMemoryMailOutbox;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class MailOutboxCommandTest extends TestCase
{
    public function testTheLastMessagesArePrintedNewestFirst(): void
    {
        $outbox = new InMemoryMailOutbox();
        $outbox->record(new RenderedMail('ada@example.com', 'Older', 'first'));
        $outbox->record(new RenderedMail('jane@example.com', 'Your sign-in code', "Your sign-in code is 123456\n"));
        $tester = new CommandTester(new MailOutboxCommand($outbox));

        self::assertSame(Command::SUCCESS, $tester->execute(['--limit' => '1']));

        $display = $tester->getDisplay();
        self::assertStringContainsString('jane@example.com', $display);
        self::assertStringContainsString('Your sign-in code is 123456', $display);
        self::assertStringNotContainsString('Older', $display);
    }

    public function testWhatAMessageSaysIsNotConsoleMarkup(): void
    {
        $outbox = new InMemoryMailOutbox();
        $outbox->record(new RenderedMail('jane@example.com', '<error>subject</error>', '<info>text</info>'));
        $tester = new CommandTester(new MailOutboxCommand($outbox));

        $tester->execute([]);

        self::assertStringContainsString('<error>subject</error>', $tester->getDisplay());
        self::assertStringContainsString('<info>text</info>', $tester->getDisplay());
    }

    public function testAnEmptyOutboxAndABadLimitAreSaidPlainly(): void
    {
        $tester = new CommandTester(new MailOutboxCommand(new InMemoryMailOutbox()));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('The outbox is empty', $tester->getDisplay());
        self::assertSame(Command::INVALID, $tester->execute(['--limit' => 'lots']));
    }
}
