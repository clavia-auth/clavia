<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Cli;

use Clavia\Adapter\Primary\Cli\AssignRoleCommand;
use Clavia\Adapter\Primary\Cli\CreateRoleCommand;
use Clavia\Adapter\Primary\Cli\ListRolesCommand;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Application\Management\Roles\ReadRoles;
use Clavia\Application\Management\Roles\RolePermissions;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class RoleCommandsTest extends TestCase
{
    private const string MANAGEMENT_API = 'https://management.clavia.test/api/v1/';

    private InMemoryResourceServerRepository $apis;
    private InMemoryUserRepository $users;
    private InMemoryRoleRepository $roles;
    private FrozenClock $clock;
    private SecretGenerator $secrets;

    #[\Override]
    protected function setUp(): void
    {
        $this->apis = new InMemoryResourceServerRepository();
        $this->users = new InMemoryUserRepository();
        $this->roles = new InMemoryRoleRepository($this->apis, $this->users);
        $this->clock = new FrozenClock();
        $this->secrets = new SecretGenerator(new SeededRandomSource(1));
    }

    public function testCreatingARoleDefaultsToEveryManagementPermission(): void
    {
        $this->registerManagementApi();
        $tester = $this->createCommand();

        self::assertSame(Command::SUCCESS, $tester->execute(['name' => 'Administrator']));

        $display = $tester->getDisplay(true);
        self::assertMatchesRegularExpression("/^Role 'Administrator' \\(rol_[A-Za-z0-9]{16}\\) grants:$/m", $display);
        self::assertStringContainsString("  update:roles\n", $display);
        self::assertStringContainsString("clavia roles:assign 'Administrator' <email>", $display);
    }

    public function testCreatingARoleTakesTheApiAndThePermissionsFromTheOptions(): void
    {
        $this->registerManagementApi();
        $tester = $this->createCommand();

        $exit = $tester->execute([
            'name' => 'Support',
            '--description' => 'Help desk',
            '--scope' => 'read:users read:clients',
        ]);

        self::assertSame(Command::SUCCESS, $exit);
        self::assertSame('Help desk', $this->roles->findByName('Support')?->description);
        self::assertSame(['  read:clients', '  read:users'], array_values(array_filter(
            explode("\n", $tester->getDisplay(true)),
            static fn (string $line): bool => str_starts_with($line, '  '),
        )));
    }

    public function testCreatingARoleSaysWhatIsWrong(): void
    {
        $tester = $this->createCommand();

        self::assertSame(Command::FAILURE, $tester->execute(['name' => 'Administrator']));
        self::assertStringContainsString('Run `clavia management-api:register` first.', $tester->getDisplay(true));

        $this->registerManagementApi();
        self::assertSame(Command::FAILURE, $tester->execute(['name' => 'Ghost', '--scope' => 'launch:missiles']));
        self::assertStringContainsString('does not define: launch:missiles', $tester->getDisplay(true));
    }

    public function testAssigningARoleListsWhatTheUserNowHolds(): void
    {
        $this->registerManagementApi();
        $this->createCommand()->execute(['name' => 'Support', '--scope' => 'read:users']);
        $this->users->save(User::register(
            UserId::generate(new SeededRandomSource(2)),
            'jane@example.com',
            null,
            $this->clock->now(),
        ));
        $tester = new CommandTester(new AssignRoleCommand(new AssignRole($this->roles, $this->users, $this->clock)));

        self::assertSame(Command::SUCCESS, $tester->execute(['role' => 'Support', 'email' => 'jane@example.com']));
        self::assertSame("jane@example.com now holds: Support\n", $tester->getDisplay(true));

        self::assertSame(Command::FAILURE, $tester->execute(['role' => 'Support', 'email' => 'nobody@example.com']));
        self::assertStringContainsString('No such user.', $tester->getDisplay(true));
    }

    public function testListingRoles(): void
    {
        $read = new ReadRoles($this->roles, new RolePermissions($this->apis));
        $tester = new CommandTester(new ListRolesCommand($read));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertSame("No roles. Create one with `clavia roles:create`.\n", $tester->getDisplay(true));

        $this->registerManagementApi();
        $this->createCommand()->execute(['name' => 'Support', '--scope' => 'read:users', '--description' => 'Help']);
        $tester->execute([]);
        self::assertMatchesRegularExpression(
            '/\| Support \| rol_[A-Za-z0-9]{16} \| 1 +\| Help +\|/',
            $tester->getDisplay(true),
        );
    }

    private function createCommand(): CommandTester
    {
        return new CommandTester(new CreateRoleCommand(
            new EnsureRole($this->roles, $this->apis, new InMemoryTransactionManager(), $this->secrets, $this->clock),
            self::MANAGEMENT_API,
        ));
    }

    private function registerManagementApi(): void
    {
        (new RegisterManagementApi(
            $this->apis,
            new InMemoryTransactionManager(),
            $this->secrets,
            $this->clock,
            Audience::fromString(self::MANAGEMENT_API),
        ))();
    }
}
