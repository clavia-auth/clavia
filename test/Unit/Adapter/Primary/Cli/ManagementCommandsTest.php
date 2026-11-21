<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\GrantClientAccessCommand;
use Clavia\Adapter\Primary\Cli\ListManagementScopesCommand;
use Clavia\Adapter\Primary\Cli\RegisterManagementApiCommand;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * `management-api:register`, `management-api:scopes` and `clients:grant`.
 */
final class ManagementCommandsTest extends TestCase
{
    private const string MANAGEMENT_API = 'https://management.clavia.test/api/v1/';
    private const string ISSUER = 'https://auth.clavia.test';

    private InMemoryClientRepository $clients;
    private InMemoryClientGrantRepository $grants;
    private InMemoryResourceServerRepository $apis;

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->grants = new InMemoryClientGrantRepository();
        $this->apis = new InMemoryResourceServerRepository($this->grants);
    }

    public function testScopesListsEveryPermissionWithWhatItAllows(): void
    {
        $tester = new CommandTester(new ListManagementScopesCommand());

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        $lines = explode("\n", trim($tester->getDisplay(true)));
        self::assertCount(count(ManagementPermission::cases()), $lines);
        self::assertMatchesRegularExpression('/^read:users +View end users$/D', $lines[0]);
    }

    public function testRegisterReportsTheIdentifierAndScopes(): void
    {
        $tester = new CommandTester(new RegisterManagementApiCommand($this->registerManagementApi()));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        $display = $tester->getDisplay(true);
        self::assertStringContainsString('Management API registered as ' . self::MANAGEMENT_API, $display);
        self::assertStringContainsString('read:users', $tester->getDisplay(true));
        self::assertTrue($this->apis->findByIdentifier(Audience::fromString(self::MANAGEMENT_API))?->isSystem);
    }

    public function testGrantDefaultsToTheManagementApiAndEveryScope(): void
    {
        ($this->registerManagementApi())();
        $this->machineClient();

        $tester = $this->grantCommand();

        self::assertSame(Command::SUCCESS, $tester->execute(['client_id' => 'machine']));
        self::assertStringContainsString('Granted machine on ' . self::MANAGEMENT_API, $tester->getDisplay(true));
        self::assertStringContainsString('-d audience=' . self::MANAGEMENT_API, $tester->getDisplay(true));
    }

    public function testGrantTakesTheScopesItIsGiven(): void
    {
        ($this->registerManagementApi())();
        $this->machineClient();

        $tester = $this->grantCommand();

        self::assertSame(Command::SUCCESS, $tester->execute(['client_id' => 'machine', '--scope' => 'read:users']));
        self::assertStringContainsString("  read:users\n", $tester->getDisplay(true));
    }

    public function testGrantPointsAtRegisterWhenTheManagementApiIsMissing(): void
    {
        $this->machineClient();

        $tester = $this->grantCommand();

        self::assertSame(Command::FAILURE, $tester->execute(['client_id' => 'machine']));
        self::assertStringContainsString('management-api:register', $tester->getDisplay(true));
    }

    public function testGrantReportsAScopeTheApiDoesNotDefine(): void
    {
        ($this->registerManagementApi())();
        $this->machineClient();

        $tester = $this->grantCommand();

        $exit = $tester->execute(['client_id' => 'machine', '--scope' => 'read:everything']);
        self::assertSame(Command::FAILURE, $exit);
        self::assertStringContainsString('does not define: read:everything', $tester->getDisplay(true));
    }

    private function grantCommand(): CommandTester
    {
        return new CommandTester(new GrantClientAccessCommand(
            new GrantClientAccess(
                $this->clients,
                $this->apis,
                $this->grants,
                new FrozenClock(),
                new InMemoryDomainEvents(),
            ),
            self::MANAGEMENT_API,
            self::ISSUER,
        ));
    }

    private function registerManagementApi(): RegisterManagementApi
    {
        return new RegisterManagementApi(
            $this->apis,
            new InMemoryTransactionManager(),
            new SecretGenerator(new SeededRandomSource(1)),
            new FrozenClock(),
            Audience::fromString(self::MANAGEMENT_API),
            new InMemoryDomainEvents(),
        );
    }

    private function machineClient(): void
    {
        $this->clients->save(Client::register(
            ClientId::fromString('machine'),
            'Machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            'hash',
            [],
            [GrantType::ClientCredentials],
            [],
            new FrozenClock()->now(),
        ));
    }
}
