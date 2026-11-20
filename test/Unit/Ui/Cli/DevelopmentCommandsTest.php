<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Ui\Cli;

use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Ui\Cli\AuthorizeUrlCommand;
use Clavia\Ui\Cli\SeedDevelopmentDataCommand;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class DevelopmentCommandsTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';

    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private FakePasswordHasher $hasher;

    #[\Override]
    protected function setUp(): void
    {
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->hasher = new FakePasswordHasher();
    }

    // ── seed-dev ────────────────────────────────────────────────────────────────

    public function testSeedCreatesTheDefaultUserAndClientAndSaysHowToSignIn(): void
    {
        $tester = $this->seedCommand();

        self::assertSame(Command::SUCCESS, $tester->execute([]));

        $client = $this->clients->findByName(SeedDevelopmentData::CLIENT_NAME);
        self::assertNotNull($client);
        self::assertTrue($client->hasRedirectUri('http://localhost:3000/callback'));
        self::assertNotNull($this->users->findByEmail('dev@clavia.test'));
        self::assertSame(
            "Created user dev@clavia.test\n"
            . "Created public client {$client->id->value}\n"
            . "\n"
            . "Seeded. Sign in at https://auth.clavia.test/auth/login as dev@clavia.test / devpassword\n"
            . "Run `clavia authorize-url` to get a link that exercises the whole flow.\n",
            $tester->getDisplay(true),
        );
    }

    public function testSeedTakesItsValuesFromTheOptions(): void
    {
        $tester = $this->seedCommand();

        $exit = $tester->execute([
            '--email' => 'jane@example.com',
            '--password' => 'hunter2hunter2',
            '--redirect-uri' => 'https://app.example/cb',
        ]);

        $user = $this->users->findByEmail('jane@example.com');
        self::assertSame(Command::SUCCESS, $exit);
        self::assertTrue($this->hasher->verify('hunter2hunter2', (string) $user?->passwordHash()));
        self::assertTrue(
            $this->clients->findByName(SeedDevelopmentData::CLIENT_NAME)?->hasRedirectUri('https://app.example/cb'),
        );
    }

    public function testSeedingTwiceSaysThatBothAlreadyExist(): void
    {
        $this->seedCommand()->execute([]);
        $tester = $this->seedCommand();

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('User dev@clavia.test already exists', $tester->getDisplay(true));
        self::assertMatchesRegularExpression('/Client [A-Za-z0-9]{32} already exists/', $tester->getDisplay(true));
    }

    public function testSeedRefusesOutsideDevelopmentAndCreatesNothing(): void
    {
        $tester = $this->seedCommand(isDevelopment: false);

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString('outside a development deployment', $tester->getDisplay(true));
        self::assertNull($this->users->findByEmail('dev@clavia.test'));
    }

    public function testSeedReportsAnInvalidOptionInsteadOfATrace(): void
    {
        $tester = $this->seedCommand();

        self::assertSame(Command::FAILURE, $tester->execute(['--redirect-uri' => 'not a url']));
        self::assertStringContainsString('A URL must', $tester->getDisplay(true));
    }

    // ── authorize-url ───────────────────────────────────────────────────────────

    public function testAuthorizeUrlPrintsALinkAndTheMatchingCurlCommand(): void
    {
        $this->seedCommand()->execute([]);
        $clientId = (string) $this->clients->findByName(SeedDevelopmentData::CLIENT_NAME)?->id->value;
        $tester = $this->authorizeUrlCommand();

        self::assertSame(Command::SUCCESS, $tester->execute([]));

        $display = $tester->getDisplay(true);
        self::assertSame(1, preg_match('#^   (https://auth\.clavia\.test/oauth2/authorize\?\S+)$#m', $display, $link));
        parse_str((string) parse_url($link[1], PHP_URL_QUERY), $query);
        self::assertSame('code', $query['response_type']);
        self::assertSame($clientId, $query['client_id']);
        self::assertSame('http://localhost:3000/callback', $query['redirect_uri']);
        self::assertSame('openid profile email', $query['scope']);
        self::assertSame('S256', $query['code_challenge_method']);

        // The verifier the curl command sends is the one the link's challenge was made from.
        self::assertSame(1, preg_match('/-d code_verifier=(\S+)/', $display, $verifier));
        self::assertSame(
            $query['code_challenge'],
            CodeChallenge::forVerifier(CodeVerifier::fromString($verifier[1]))->value,
        );
        self::assertStringContainsString("-d client_id={$clientId} ", $display);
        self::assertStringContainsString('-d redirect_uri=http://localhost:3000/callback ', $display);
        self::assertStringNotContainsString('NOTE', $display);
    }

    public function testAuthorizeUrlTakesItsValuesFromTheOptions(): void
    {
        $tester = $this->authorizeUrlCommand();

        $exit = $tester->execute([
            '--client-id' => 'mine',
            '--redirect-uri' => 'https://app.example/cb',
            '--scope' => 'openid',
        ]);

        self::assertSame(Command::SUCCESS, $exit);
        self::assertStringContainsString(
            'client_id=mine&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&scope=openid&',
            $tester->getDisplay(true),
        );
    }

    public function testAuthorizeUrlWarnsWhenAutoLoginWouldSkipTheLoginPage(): void
    {
        $this->seedCommand()->execute([]);
        $tester = $this->authorizeUrlCommand('dev@clavia.test');

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString(
            "NOTE: CLAVIA_DEV_AUTOLOGIN_EMAIL is set to 'dev@clavia.test'",
            $tester->getDisplay(true),
        );
    }

    public function testAuthorizeUrlSaysWhatToDoWhenThereIsNoClient(): void
    {
        $tester = $this->authorizeUrlCommand();

        self::assertSame(Command::FAILURE, $tester->execute([]));
        self::assertStringContainsString(
            'Run `clavia seed-dev` first, or pass --client-id.',
            $tester->getDisplay(true),
        );
    }

    public function testAuthorizeUrlReportsAnInvalidOptionInsteadOfATrace(): void
    {
        $tester = $this->authorizeUrlCommand();

        self::assertSame(Command::FAILURE, $tester->execute(['--client-id' => 'not an id']));
        self::assertStringContainsString('A client id is', $tester->getDisplay(true));
    }

    private function seedCommand(bool $isDevelopment = true): CommandTester
    {
        $random = new SeededRandomSource(1);

        return new CommandTester(new SeedDevelopmentDataCommand(
            new SeedDevelopmentData(
                $this->users,
                $this->clients,
                $this->hasher,
                new InMemoryTransactionManager(),
                new SecretGenerator($random),
                $random,
                new FrozenClock(),
                $isDevelopment,
            ),
            'clavia.test',
            self::ISSUER,
        ));
    }

    private function authorizeUrlCommand(?string $devAutologinEmail = null): CommandTester
    {
        $random = new SeededRandomSource(2);

        return new CommandTester(new AuthorizeUrlCommand(
            new BuildAuthorizationUrl(
                $this->clients,
                new SecretGenerator($random),
                $random,
                ScopeSet::fromString('openid profile email'),
            ),
            self::ISSUER,
            $devAutologinEmail,
        ));
    }
}
