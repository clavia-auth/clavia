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
use Clavia\Application\Management\Provisioning\GrantClientAccess;
use Clavia\Application\Management\Provisioning\RegisterManagementApi;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\FakePasswordHasher;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use LogicException;
use PHPUnit\Framework\TestCase;

final class SeedManagementAccessTest extends TestCase
{
    private InMemoryClientRepository $clients;
    private InMemoryResourceServerRepository $apis;
    private InMemoryClientGrantRepository $grants;
    private FakePasswordHasher $hasher;

    #[\Override]
    protected function setUp(): void
    {
        $this->clients = new InMemoryClientRepository();
        $this->grants = new InMemoryClientGrantRepository();
        $this->apis = new InMemoryResourceServerRepository($this->grants);
        $this->hasher = new FakePasswordHasher();
    }

    public function testItRegistersTheApiAndAMachineClientHoldingEveryScopeOnIt(): void
    {
        $seeded = $this->seeder()();

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

    public function testRunningItAgainKeepsTheClient(): void
    {
        $first = $this->seeder()();
        $second = $this->seeder()();

        self::assertFalse($second->clientCreated);
        self::assertTrue($second->clientId->equals($first->clientId));
        self::assertCount(1, $this->clients->all());
    }

    public function testItRefusesOutsideADevelopmentDeployment(): void
    {
        try {
            $this->seeder(isDevelopment: false)();
            self::fail('Development access was seeded.');
        } catch (LogicException) {
            self::assertSame([], $this->clients->all());
        }
    }

    private function seeder(bool $isDevelopment = true): SeedManagementAccess
    {
        $clock = new FrozenClock();
        $secrets = new SecretGenerator(new SeededRandomSource(count($this->clients->all()) + 1));

        return new SeedManagementAccess(
            $this->clients,
            new RegisterManagementApi(
                $this->apis,
                new InMemoryTransactionManager(),
                $secrets,
                $clock,
                Audience::fromString('https://management.clavia.test/api/v1/'),
            ),
            new RegisterMachineClient($this->clients, $this->hasher, $secrets, $clock),
            new GrantClientAccess($this->clients, $this->apis, $this->grants, $clock),
            new InMemoryTransactionManager(),
            $isDevelopment,
        );
    }
}
