<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authorization;

use Clavia\Application\Authorization\Feed\IdentityFeed;
use Clavia\Application\Authorization\Feed\ResyncStore;
use Clavia\Application\Authorization\Feed\StoreReconciler;
use Clavia\Application\Authorization\Feed\SyncIdentityFeed;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\Event\AuthorizationEnabled;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\Event\ClientDeleted;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Identity\Event\UserDeleted;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\Event\RoleChanged;
use Clavia\Domain\Rbac\Event\RoleDeleted;
use Clavia\Domain\Rbac\Event\RoleGiven;
use Clavia\Domain\Rbac\Event\RoleTaken;
use Clavia\Domain\Rbac\Event\UserRolesReplaced;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Scope;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryIdentityFeedOutbox;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use Closure;
use PHPUnit\Framework\TestCase;

/**
 * The identity feed (#137, docs/design/fine-grained-authorization.md §5.4): what Clavia knows of who
 * holds which role, and of who exists, kept in step in each API's store, against the decision
 * engine's double.
 */
final class IdentityFeedTest extends TestCase
{
    /** People, applications, roles, and documents people, applications and roles' members may view. */
    private const string MODEL = <<<'JSON'
        {
          "schema_version": "1.1",
          "type_definitions": [
            {"type": "user"},
            {"type": "client"},
            {
              "type": "role",
              "relations": {"member": {"this": {}}},
              "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}
            },
            {
              "type": "document",
              "relations": {"viewer": {"this": {}}},
              "metadata": {"relations": {"viewer": {"directly_related_user_types": [
                {"type": "user"}, {"type": "client"}, {"type": "role", "relation": "member"}
              ]}}}
            }
          ]
        }
        JSON;

    private const string ADA = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a01';
    private const string BOB = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a02';
    private const string ADA_EDITS = 'role:rol_EDITORSEDITORS01#member@user:' . self::ADA;
    private const string BOB_EDITS = 'role:rol_EDITORSEDITORS01#member@user:' . self::BOB;
    private const string ADA_BILLS = 'role:rol_BILLINGBILLING01#member@user:' . self::ADA;

    private FrozenClock $clock;
    private FakeDecisionEngine $engine;
    private InMemoryIdentityFeedOutbox $outbox;
    private InMemoryResourceServerRepository $apis;
    private InMemoryUserRepository $users;
    private InMemoryClientRepository $clients;
    private InMemoryRoleRepository $roles;
    private InMemoryDomainEvents $events;
    private StoreReconciler $reconciler;

    /** @var list<Closure(): void> What would run after the response. */
    private array $afterResponse = [];

    private ResourceServer $documents;
    private ResourceServer $invoices;
    private Role $editors;
    private Role $billing;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-11-28T10:00:00Z');
        $this->engine = new FakeDecisionEngine();
        $this->outbox = new InMemoryIdentityFeedOutbox();
        $this->apis = new InMemoryResourceServerRepository(null, $this->outbox);
        $this->users = new InMemoryUserRepository();
        $this->clients = new InMemoryClientRepository();
        $this->roles = new InMemoryRoleRepository($this->apis, $this->users);
        $this->reconciler = new StoreReconciler($this->engine, $this->roles, $this->users, $this->clients);
        $this->events = new InMemoryDomainEvents($this->feed(true));

        $this->documents = $this->apiWithAStore('https://documents.example/api/', 'read:documents');
        $this->invoices = $this->apiWithAStore('https://invoices.example/api/', 'read:invoices');
        // An API without authorization is never written to.
        $this->apis->save($this->api('https://reports.example/api/', 'read:reports'));
        $this->editors = $this->role('rol_EDITORSEDITORS01', 'Editors', $this->documents, 'read:documents');
        $this->billing = $this->role('rol_BILLINGBILLING01', 'Billing', $this->invoices, 'read:invoices');
        $this->person(self::ADA, 'ada@example.com');
        $this->person(self::BOB, 'bob@example.com');
    }

    public function testARoleGivenReachesTheStoresOfTheApisItHoldsAPermissionOnOnly(): void
    {
        $this->give($this->editors, self::ADA);

        self::assertSame([$this->documents->id->value . ' user:' . self::ADA], $this->outbox->waiting());
        self::assertSame([], $this->relationshipsIn($this->documents), 'Nothing is sent before the response.');

        $this->respond();

        self::assertSame([self::ADA_EDITS], $this->relationshipsIn($this->documents));
        self::assertSame([], $this->relationshipsIn($this->invoices));
        self::assertSame(0, $this->outbox->pending());
    }

    public function testARoleTakenLeavesTheStore(): void
    {
        $this->give($this->editors, self::ADA);
        $this->give($this->editors, self::BOB);
        $this->respond();

        $this->roles->unassign($this->editors->id, UserId::fromString(self::ADA));
        $this->events->dispatch(new RoleTaken($this->editors->id, UserId::fromString(self::ADA)));
        $this->respond();

        self::assertSame([self::BOB_EDITS], $this->relationshipsIn($this->documents));
    }

    public function testRolesReplacedAreWorkedOutInEveryStore(): void
    {
        $this->give($this->editors, self::ADA);
        $this->respond();

        $this->roles->replaceRolesOf(UserId::fromString(self::ADA), [$this->billing->id], $this->clock->now());
        $this->events->dispatch(new UserRolesReplaced(UserId::fromString(self::ADA), [$this->billing->id]));
        $this->respond();

        self::assertSame([], $this->relationshipsIn($this->documents));
        self::assertSame([self::ADA_BILLS], $this->relationshipsIn($this->invoices));
    }

    public function testARoleWhosePermissionsMoveTakesItsMembersAlong(): void
    {
        $this->give($this->editors, self::ADA);
        $this->give($this->editors, self::BOB);
        $this->respond();

        $this->roles->save($this->editors->granting([self::granted($this->invoices, 'read:invoices')]));
        // A rename alone touches no store.
        $this->events->dispatch(new RoleChanged($this->editors->id, ['name']));
        self::assertSame(0, $this->outbox->pending());
        $this->events->dispatch(new RoleChanged($this->editors->id, ['permissions']));
        $this->respond();

        self::assertSame([], $this->relationshipsIn($this->documents));
        self::assertSame([
            self::ADA_EDITS,
            self::BOB_EDITS,
        ], $this->relationshipsIn($this->invoices));
    }

    public function testADeletedRoleLeavesNoMember(): void
    {
        $this->give($this->editors, self::ADA);
        $this->respond();

        $this->roles->delete($this->editors->id);
        $this->events->dispatch(new RoleDeleted($this->editors));
        $this->respond();

        self::assertSame([], $this->relationshipsIn($this->documents));
    }

    public function testADeletedAccountLosesEveryRelationshipNamingIt(): void
    {
        $this->give($this->editors, self::ADA);
        $this->respond();
        // Written by the API itself, in both stores.
        $this->write($this->documents, 'document:1#viewer@user:' . self::ADA, 'document:1#viewer@user:' . self::BOB);
        $this->write($this->invoices, 'document:7#viewer@user:' . self::ADA);
        $ada = $this->users->find(UserId::fromString(self::ADA));
        self::assertNotNull($ada);

        $this->users->delete($ada->id);
        $this->events->dispatch(new UserDeleted($ada));
        $this->respond();

        self::assertSame(['document:1#viewer@user:' . self::BOB], $this->relationshipsIn($this->documents));
        self::assertSame([], $this->relationshipsIn($this->invoices));
    }

    public function testADeletedApplicationLosesEveryRelationshipNamingIt(): void
    {
        $client = $this->application('reports-job');
        $this->write($this->documents, 'document:1#viewer@client:reports-job', 'document:1#viewer@user:' . self::BOB);

        $this->clients->delete($client->id);
        $this->events->dispatch(new ClientDeleted($client));
        $this->respond();

        self::assertSame(['document:1#viewer@user:' . self::BOB], $this->relationshipsIn($this->documents));
    }

    public function testWhatTheEngineDidNotTakeWaitsAndIsSentLater(): void
    {
        $this->engine->goDown();
        $this->give($this->editors, self::ADA);
        $this->respond();

        self::assertSame(1, $this->outbox->pending(), 'A committed change is never lost.');
        $sync = $this->sync();
        self::assertSame(0, $sync()->sent, 'Not due again before five seconds.');

        $this->engine->comeBack();
        $this->clock->advance(5);
        $run = $sync();

        self::assertSame(1, $run->sent);
        self::assertSame(0, $run->pending);
        self::assertSame([self::ADA_EDITS], $this->relationshipsIn($this->documents));
    }

    public function testFailuresBackOffAndAreNeverGivenUp(): void
    {
        $this->engine->goDown();
        $this->give($this->editors, self::ADA);
        $sync = $this->sync();

        foreach ([5, 60, 300, 600, 600, 600] as $delay) {
            self::assertSame(1, $sync()->failed);
            $this->clock->advance($delay - 1);
            self::assertSame(0, $sync()->failed, 'Waiting its turn.');
            $this->clock->advance(1);
        }
        $this->clock->advance(86_400);
        self::assertSame(1, $sync()->failed, 'Still tried a day later.');
    }

    public function testEnablingAnApiWritesTheMembersOfEveryRoleThatReachesIt(): void
    {
        $this->roles->assign($this->editors->id, UserId::fromString(self::ADA), $this->clock->now());
        $this->roles->assign($this->billing->id, UserId::fromString(self::BOB), $this->clock->now());

        $this->events->dispatch(new AuthorizationEnabled($this->documents->id, $this->storeOf($this->documents)));
        $this->respond();

        self::assertSame([self::ADA_EDITS], $this->relationshipsIn($this->documents));
        self::assertSame([], $this->relationshipsIn($this->invoices));
    }

    public function testAResyncRepairsADriftAndThenHasNothingToDo(): void
    {
        $this->roles->assign($this->editors->id, UserId::fromString(self::ADA), $this->clock->now());
        // Someone the role does not name, and nobody for the person it does.
        $this->write($this->documents, self::BOB_EDITS);
        $resync = new ResyncStore($this->apis, $this->reconciler, true);

        $first = $resync('https://documents.example/api/');
        $second = $resync($this->documents->id->value);

        self::assertSame([1, 1], [$first->written, $first->deleted]);
        self::assertSame([0, 0], [$second->written, $second->deleted]);
        self::assertSame([self::ADA_EDITS], $this->relationshipsIn($this->documents));
    }

    public function testWhatHappensWhileFineGrainedAuthorizationIsOffIsSentOnceItIsOn(): void
    {
        $events = new InMemoryDomainEvents($this->feed(false));
        $this->roles->assign($this->editors->id, UserId::fromString(self::ADA), $this->clock->now());

        $events->dispatch(new RoleGiven($this->editors->id, UserId::fromString(self::ADA)));

        self::assertSame(1, $this->outbox->pending(), 'Queued, for the store the API kept.');
        self::assertSame([], $this->afterResponse, 'Nothing to send it to.');
        $off = $this->sync(false)();
        self::assertFalse($off->available);
        self::assertSame([0, 1], [$off->sent, $off->pending]);
        self::assertSame([], $this->relationshipsIn($this->documents));

        self::assertSame(1, $this->sync()()->sent);
        self::assertSame([self::ADA_EDITS], $this->relationshipsIn($this->documents));
    }

    private function feed(bool $available): IdentityFeed
    {
        $deferred = new class ($this->afterResponse) implements DeferredTasks {
            /** @param list<Closure(): void> $tasks */
            public function __construct(private array &$tasks)
            {
            }

            #[\Override]
            public function defer(Closure $task): void
            {
                $this->tasks[] = $task;
            }
        };

        return new IdentityFeed(
            $this->outbox,
            $this->apis,
            $this->roles,
            $this->sync($available),
            $deferred,
            $this->clock,
            $available,
        );
    }

    private function sync(bool $available = true): SyncIdentityFeed
    {
        return new SyncIdentityFeed($this->outbox, $this->apis, $this->reconciler, $this->clock, $available);
    }

    /** The response is sent: what was deferred runs, once. */
    private function respond(): void
    {
        while ($this->afterResponse !== []) {
            $task = array_shift($this->afterResponse);
            $task();
        }
    }

    private function give(Role $role, string $user): void
    {
        $this->roles->assign($role->id, UserId::fromString($user), $this->clock->now());
        $this->events->dispatch(new RoleGiven($role->id, UserId::fromString($user)));
    }

    /** @return list<string> */
    private function relationshipsIn(ResourceServer $api): array
    {
        return $this->engine->relationshipsIn($this->storeOf($api));
    }

    private function write(ResourceServer $api, string ...$tuples): void
    {
        $settings = $this->apis->find($api->id)?->authorization;
        self::assertNotNull($settings);
        $this->engine->write($settings->store, $settings->modelId, array_values(array_map(
            static function (string $tuple): Tuple {
                [$object, $rest] = explode('#', $tuple, 2) + [1 => ''];
                [$relation, $subject] = explode('@', $rest, 2) + [1 => ''];

                return Tuple::of(
                    ObjectRef::fromString($object),
                    Relation::fromString($relation),
                    SubjectRef::fromString($subject),
                );
            },
            $tuples,
        )));
    }

    private function storeOf(ResourceServer $api): \Clavia\Domain\Authorization\StoreId
    {
        $settings = $this->apis->find($api->id)?->authorization;
        self::assertNotNull($settings);

        return $settings->store;
    }

    private function api(string $identifier, string $permission): ResourceServer
    {
        return ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            $identifier,
            [Permission::of($permission, 'Read')],
            $this->clock->now(),
        );
    }

    private function apiWithAStore(string $identifier, string $permission): ResourceServer
    {
        $model = AuthorizationModel::fromJson(self::MODEL);
        $store = $this->engine->createStore('clavia-test');
        $api = $this->api($identifier, $permission)->withAuthorization(
            AuthorizationSettings::of(true, $store, $this->engine->writeModel($store, $model), $model, [], false),
        );
        $this->apis->save($api);

        return $api;
    }

    private function role(string $id, string $name, ResourceServer $api, string $permission): Role
    {
        $role = Role::define(
            RoleId::fromString($id),
            $name,
            '',
            [self::granted($api, $permission)],
            $this->clock->now(),
        );
        $this->roles->save($role);

        return $role;
    }

    private static function granted(ResourceServer $api, string $permission): GrantedPermission
    {
        return new GrantedPermission($api->id, Scope::fromString($permission));
    }

    private function person(string $id, string $email): void
    {
        $this->users->save(User::register(UserId::fromString($id), $email, null, $this->clock->now()));
    }

    private function application(string $id): Client
    {
        $client = Client::register(
            ClientId::fromString($id),
            $id,
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            'hash',
            [],
            [GrantType::ClientCredentials],
            [],
            $this->clock->now(),
        );
        $this->clients->save($client);

        return $client;
    }
}
