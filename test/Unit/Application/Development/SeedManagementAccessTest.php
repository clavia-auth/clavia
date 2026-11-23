<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Development;

use Clavia\Application\Clients\RegisterMachineClient;
use Clavia\Application\Development\SeedManagementAccess;
use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\AssignRole;
use Clavia\Application\Management\Provisioning\EnsureRole;
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

final class SeedManagementAccessTest extends TestCase
{
    private const string ADMINISTRATOR = 'dev@clavia.test';

    private InMemoryClientRepository $clients;
    private InMemoryResourceServerRepository $apis;
    private InMemoryClientGrantRepository $grants;
    private InMemoryUserRepository $users;
    private InMemoryRoleRepository $roles;
    private FakePasswordHasher $hasher;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->grants = new InMemoryClientGrantRepository();
        $this->apis = new InMemoryResourceServerRepository($this->grants);
        $this->users = new InMemoryUserRepository();
        $this->roles = new InMemoryRoleRepository($this->apis, $this->users);
        $this->hasher = new FakePasswordHasher();
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(9)),
            self::ADMINISTRATOR,
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->users->save($this->user);
    }

    public function testItRegistersTheApiAndAMachineClientHoldingEveryScopeOnIt(): void
    {
        $seeded = $this->seeder()(self::ADMINISTRATOR);

        $client = $this->clients->find($seeded->clientId);
        $api = $this->apis->findByIdentifier($seeded->managementApi);
        self::assertTrue($seeded->clientCreated);
        self::assertNotNull($client);
        self::assertNotNull($api);
        self::assertSame(SeedManagementAccess::CLIENT_NAME, $client->name);
        self::assertTrue($this->hasher->verify(SeedManagementAccess::CLIENT_SECRET, (string) $client->secretHash()));
        self::assertCount(count(ManagementPermission::cases()), $seeded->scopes->toList());
        self::assertSame(
            $seeded->scopes->toString(),
            $this->grants->find($client->id, $api->id)?->scopes->toString(),
        );
    }

    public function testTheAdministratorHoldsEveryManagementPermissionThroughARole(): void
    {
        $seeded = $this->seeder()(self::ADMINISTRATOR);
        $api = $this->apis->findByIdentifier($seeded->managementApi);
        self::assertNotNull($api);

        self::assertSame(
            [SeedManagementAccess::ADMINISTRATOR_ROLE],
            array_map(static fn (Role $role): string => $role->name, $this->roles->rolesOf($this->user->id)),
        );
        self::assertTrue($this->roles->permissionsHeld($this->user->id, $api->id)->equals($api->permissionScopes()));
    }

    public function testTheManagementApiRequiresMoreThanOneFactor(): void
    {
        // So the dashboard's step-up is exercised in development (docs/design/mfa-policies.md §10, 3).
        $seeded = ($this->seeder())(self::ADMINISTRATOR);

        self::assertSame(MfaPolicy::Required, $this->apis->findByIdentifier($seeded->managementApi)?->mfaPolicy);
    }

    public function testRunningItAgainKeepsTheClientAndTheRole(): void
    {
        $first = $this->seeder()(self::ADMINISTRATOR);
        $second = $this->seeder()(self::ADMINISTRATOR);

        self::assertFalse($second->clientCreated);
        self::assertTrue($second->clientId->equals($first->clientId));
        self::assertCount(1, $this->clients->all());
        self::assertCount(1, $this->roles->all());
    }

    public function testAnAdministratorWithoutAnAccountIsRefused(): void
    {
        $this->expectException(NotFound::class);

        $this->seeder()('nobody@clavia.test');
    }

    public function testItRefusesOutsideADevelopmentDeployment(): void
    {
        try {
            $this->seeder(isDevelopment: false)(self::ADMINISTRATOR);
            self::fail('Development access was seeded.');
        } catch (LogicException) {
            self::assertSame([], $this->clients->all());
            self::assertSame([], $this->roles->all());
        }
    }

    private function seeder(bool $isDevelopment = true): SeedManagementAccess
    {
        $clock = new FrozenClock();
        $secrets = new SecretGenerator(new SeededRandomSource(count($this->clients->all()) + 1));
        $transactions = new InMemoryTransactionManager();

        return new SeedManagementAccess(
            $this->clients,
            $this->apis,
            new RegisterManagementApi(
                $this->apis,
                $transactions,
                $secrets,
                $clock,
                Audience::fromString('https://management.clavia.test/api/v1/'),
                new InMemoryDomainEvents(),
            ),
            new RegisterMachineClient($this->clients, $this->hasher, $secrets, $clock, new InMemoryDomainEvents()),
            new GrantClientAccess($this->clients, $this->apis, $this->grants, $clock, new InMemoryDomainEvents()),
            new EnsureRole($this->roles, $this->apis, $transactions, $secrets, $clock, new InMemoryDomainEvents()),
            new AssignRole($this->roles, $this->users, $clock, new InMemoryDomainEvents()),
            $transactions,
            $isDevelopment,
        );
    }
}
