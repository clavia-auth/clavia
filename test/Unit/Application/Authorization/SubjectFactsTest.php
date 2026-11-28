<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authorization;

use Clavia\Application\Authorization\Evaluation\SubjectFacts;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Scope;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * What Clavia tells the engine of a question's subject (#138, docs/design/fine-grained-authorization.md
 * §2, "Context and conditions"): cut to the API asking, and nothing of a subject that is not one.
 */
final class SubjectFactsTest extends TestCase
{
    private const string ADA = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a01';

    private FrozenClock $clock;
    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private InMemoryRoleRepository $roles;
    private SubjectFacts $facts;
    private ResourceServer $documents;
    private ResourceServer $invoices;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-11-28T10:00:00Z');
        $apis = new InMemoryResourceServerRepository();
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->roles = new InMemoryRoleRepository($apis, $this->users);
        $this->facts = new SubjectFacts(
            $this->users,
            $this->clients,
            $this->roles,
            new InMemoryMfaFactorRepository(new InMemoryTransactionManager()),
            new InMemoryPasskeyRepository(),
        );
        $this->documents = $this->api('https://documents.example/api/');
        $this->invoices = $this->api('https://invoices.example/api/');
        $apis->save($this->documents);
        $apis->save($this->invoices);
    }

    public function testAPersonsFactsNameOnlyTheRolesOfTheApiAsking(): void
    {
        $ada = User::register(UserId::fromString(self::ADA), 'ada@example.com', null, $this->clock->now());
        $ada->changeAppMetadata(AppMetadata::fromJson('{"department": "finance"}'), $this->clock->now());
        $this->users->save($ada);
        $this->role('rol_EDITORSEDITORS01', 'Editors', $this->documents);
        $this->role('rol_BILLINGBILLING01', 'Billing', $this->invoices);

        $facts = $this->facts->of($this->documents, 'user', self::ADA);

        self::assertNotNull($facts);
        self::assertSame(self::ADA, $facts['id']);
        self::assertSame('password', $facts['connection']);
        self::assertSame(['Editors'], $facts['roles']);
        self::assertFalse($facts['mfa_enrolled']);
        self::assertEquals((object) ['department' => 'finance'], $facts['app_metadata']);
    }

    public function testEmptyApplicationMetadataIsStillAnObject(): void
    {
        $this->users->save(User::register(UserId::fromString(self::ADA), 'ada@example.com', null, $this->clock->now()));

        $facts = $this->facts->of($this->documents, 'user', self::ADA);

        self::assertNotNull($facts);
        self::assertInstanceOf(stdClass::class, $facts['app_metadata'] ?? null);
        self::assertSame('{}', json_encode($facts['app_metadata'], JSON_THROW_ON_ERROR));
    }

    public function testAnApplicationIsDescribedByWhatItIs(): void
    {
        $this->clients->save(Client::register(
            ClientId::fromString('reports-job'),
            'Reports job',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            'hash',
            [],
            [GrantType::ClientCredentials],
            [],
            $this->clock->now(),
        ));

        self::assertSame(
            ['id' => 'reports-job', 'type' => 'confidential', 'first_party' => true],
            $this->facts->of($this->documents, 'client', 'reports-job'),
        );
    }

    public function testNothingIsSaidOfASubjectThatIsNotOne(): void
    {
        $gone = User::register(UserId::fromString(self::ADA), 'ada@example.com', null, $this->clock->now());
        $gone->deactivate($this->clock->now());
        $this->users->save($gone);

        self::assertNull($this->facts->of($this->documents, 'user', self::ADA), 'Deactivated.');
        self::assertNull($this->facts->of($this->documents, 'user', '0b7e1c55-8f3a-4c2d-9e6b-5a4f3e2d1c0b'));
        self::assertNull($this->facts->of($this->documents, 'user', 'not-a-uuid'));
        self::assertNull($this->facts->of($this->documents, 'client', 'nobody'));
        self::assertNull($this->facts->of($this->documents, 'team', 'finance'));
    }

    private function api(string $identifier): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            $identifier,
            [Permission::of('read', 'Read')],
            $this->clock->now(),
        );
    }

    private function role(string $id, string $name, ResourceServer $api): void
    {
        $role = Role::define(
            RoleId::fromString($id),
            $name,
            '',
            [new GrantedPermission($api->id, Scope::fromString('read'))],
            $this->clock->now(),
        );
        $this->roles->save($role);
        $this->roles->assign($role->id, UserId::fromString(self::ADA), $this->clock->now());
    }
}
