<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\IssueRegistrationTokenCommand;
use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\PageRequest;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryInitialAccessTokenRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class IssueRegistrationTokenCommandTest extends TestCase
{
    private InMemoryInitialAccessTokenRepository $tokens;
    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
    }

    public function testTheTokenIsPrintedOnceAndStoredAsItsDigest(): void
    {
        $tester = $this->command(registrationOpen: true);

        self::assertSame(Command::SUCCESS, $tester->execute([
            'description' => 'Acme',
            '--uses' => '3',
            '--expires-in' => '3600',
        ]));

        $display = $tester->getDisplay(true);
        self::assertSame(1, preg_match('/^  token: +([A-Za-z0-9_-]{43})$/m', $display, $match));
        self::assertStringContainsString('  registers:  3 clients', $display);
        self::assertStringContainsString('  expires at: 2026-01-15T11:00:00+00:00', $display);
        self::assertStringNotContainsString('Registration is off', $display);
        $stored = $this->tokens->page(PageRequest::of())->items;
        self::assertCount(1, $stored);
        self::assertTrue($stored[0]->digest->equals(Digest::of($match[1])));
    }

    public function testItSaysWhenRegistrationIsOff(): void
    {
        $tester = $this->command(registrationOpen: false);

        self::assertSame(Command::SUCCESS, $tester->execute(['description' => 'Acme']));

        self::assertStringContainsString('CLAVIA_CLIENT_REGISTRATION=token', $tester->getDisplay(true));
    }

    public function testWhatIsOutOfBoundsIsRefusedAndNothingIsIssued(): void
    {
        foreach ([['--uses' => '0'], ['--uses' => 'two'], ['--expires-in' => '10']] as $options) {
            $tester = $this->command(registrationOpen: true);

            self::assertSame(Command::FAILURE, $tester->execute(['description' => 'Acme'] + $options));
        }
        self::assertSame(0, $this->tokens->page(PageRequest::of())->total);
    }

    private function command(bool $registrationOpen): CommandTester
    {
        $random = new SeededRandomSource(1);

        return new CommandTester(new IssueRegistrationTokenCommand(
            new IssueInitialAccessToken(
                $this->tokens,
                new SecretGenerator($random),
                $random,
                $this->clock,
                new InMemoryDomainEvents(),
            ),
            $registrationOpen,
        ));
    }
}
