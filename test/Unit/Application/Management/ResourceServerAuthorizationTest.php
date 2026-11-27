<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Management;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Management\Provisioning\RegisterAuthorizationApi;
use Clavia\Application\Management\Provisioning\SystemApiRegistration;
use Clavia\Application\Management\ResourceServers\AuthorizationRefused;
use Clavia\Application\Management\ResourceServers\ConfigureAuthorization;
use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\DisableAuthorization;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\Event\AuthorizationDisabled;
use Clavia\Domain\Authorization\Event\AuthorizationEnabled;
use Clavia\Domain\Authorization\Event\AuthorizationModelWritten;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\ResourceServer\Event\ResourceServerChanged;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientGrantRepository;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/**
 * Fine-grained authorization on an API (docs/design/fine-grained-authorization.md §5.1): switched on
 * with a model and the clients speaking for it, switched off keeping the store, deleted on
 * confirmation; and the Authorization API those clients ask with.
 */
final class ResourceServerAuthorizationTest extends TestCase
{
    private InMemoryResourceServerRepository $apis;
    private InMemoryClientRepository $clients;
    private FakeDecisionEngine $engine;
    private InMemoryDomainEvents $events;

    #[\Override]
    protected function setUp(): void
    {
        $this->apis = new InMemoryResourceServerRepository(new InMemoryClientGrantRepository());
        $this->clients = new InMemoryClientRepository();
        $this->engine = new FakeDecisionEngine();
        $this->events = new InMemoryDomainEvents();
    }

    public function testSwitchingItOnMakesTheApiAStoreAndWritesTheModel(): void
    {
        $api = $this->anApi();

        $configured = $this->configure($api->id, clients: [$this->machine('reports-backend')]);

        $settings = $configured->authorization;
        self::assertNotNull($settings);
        self::assertTrue($settings->enabled);
        self::assertTrue($this->engine->hasStore($settings->store));
        self::assertSame(DecisionEngineContract::MODEL, $settings->model->json);
        self::assertTrue($settings->speaksFor(ClientId::fromString('reports-backend')));
        self::assertTrue($this->apis->find($api->id)?->authorizes());
        self::assertCount(1, $this->events->ofType(AuthorizationEnabled::class));
        self::assertCount(1, $this->events->ofType(AuthorizationModelWritten::class));
        $changed = $this->events->ofType(ResourceServerChanged::class);
        self::assertSame(['authorization.clients'], $changed[0]->changed ?? null);
    }

    public function testTheSameModelAgainIsNoNewVersionAndAnotherIs(): void
    {
        $api = $this->anApi();
        $first = $this->configure($api->id)->authorization;
        self::assertNotNull($first);

        // The same model, spaced and ordered otherwise: the same.
        $respaced = json_encode(json_decode(DecisionEngineContract::MODEL), JSON_THROW_ON_ERROR);
        $again = $this->configure($api->id, model: $respaced, denialReasons: true)->authorization;
        self::assertNotNull($again);
        self::assertTrue($again->modelId->equals($first->modelId));
        self::assertTrue($again->store->equals($first->store));
        self::assertCount(1, $this->events->ofType(AuthorizationModelWritten::class));
        self::assertCount(1, $this->events->ofType(AuthorizationEnabled::class), 'It was on already.');
        self::assertTrue($again->denialReasons);

        $other = str_replace(
            '"owner": {"directly_related_user_types": [{"type": "user"}]}',
            '"owner": {"directly_related_user_types": [{"type": "user"}, {"type": "team", "relation": "member"}]}',
            DecisionEngineContract::MODEL,
        );
        $next = $this->configure($api->id, model: $other)->authorization;
        self::assertNotNull($next);
        self::assertFalse($next->modelId->equals($first->modelId));
        self::assertTrue($next->store->equals($first->store), 'One store per API, kept.');
        self::assertCount(2, $this->events->ofType(AuthorizationModelWritten::class));
        self::assertSame(1, $this->engine->storeCount());
    }

    public function testASystemApiIsRefusedBeforeTheEngineIsAsked(): void
    {
        $system = ResourceServer::register(
            ResourceServerId::fromString('rs_mmmmmmmmmmmmmmmm'),
            Audience::fromString('https://management.clavia.test/api/v1/'),
            'Management API',
            [Permission::of('read:users')],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            isSystem: true,
            enforcePolicies: true,
        );
        $this->apis->save($system);

        $this->expectException(SystemApiProtected::class);

        try {
            $this->configure($system->id);
        } finally {
            self::assertSame(0, $this->engine->storeCount());
        }
    }

    public function testWithNoEngineConfiguredItIsAConflict(): void
    {
        $api = $this->anApi();

        $this->expectException(Conflict::class);

        $this->configure($api->id, available: false);
    }

    public function testOnlyAFirstPartyMachineClientSpeaksForAnApi(): void
    {
        $api = $this->anApi();
        $browser = $this->client('reports-web', ClientType::Public, [GrantType::AuthorizationCode]);
        $thirdParty = $this->client('tpc_partner-machine', ClientType::Confidential, [GrantType::ClientCredentials]);

        foreach (
            [
            '/clients/1' => [$this->machine('reports-backend'), ClientId::fromString('nobody')],
            '/clients/0' => [$browser],
            '/clients/2' => [$this->machine('reports-jobs'), $this->machine('reports-sync'), $thirdParty],
            ] as $pointer => $clients
        ) {
            try {
                $this->configure($api->id, clients: $clients);
                self::fail('A client that cannot ask for decisions was taken.');
            } catch (AuthorizationRefused $refused) {
                self::assertSame($pointer, $refused->pointer);
            }
        }
        self::assertSame(0, $this->engine->storeCount(), 'Refused before a store was made.');
        self::assertNull($this->apis->find($api->id)?->authorization);
    }

    public function testAClientNamedTwiceIsRefused(): void
    {
        $api = $this->anApi();
        $client = $this->machine('reports-backend');

        $this->expectException(InvalidValue::class);

        try {
            $this->configure($api->id, clients: [$client, $client]);
        } finally {
            self::assertSame(0, $this->engine->storeCount(), 'The store made for it is deleted again.');
        }
    }

    public function testAClientSpeakingForAnotherApiLeavesNoStoreBehind(): void
    {
        $client = $this->machine('shared-backend');
        $this->configure($this->anApi('https://documents.test/api/')->id, clients: [$client]);

        try {
            $this->configure($this->anApi()->id, clients: [$client]);
            self::fail('A client spoke for two APIs.');
        } catch (AlreadyExists) {
            self::assertSame(1, $this->engine->storeCount());
        }
    }

    public function testAModelTheEngineRefusesPointsAtTheModelWithTheEnginesCode(): void
    {
        $api = $this->anApi();
        $broken = '{"schema_version": "1.1", "type_definitions": [{"type": "user"}, {"type": "document", '
            . '"relations": {"viewer": {"computedUserset": {"relation": "editor"}}}}]}';

        try {
            $this->configure($api->id, model: $broken);
            self::fail('The model was taken.');
        } catch (AuthorizationRefused $refused) {
            self::assertSame('/model', $refused->pointer);
            self::assertStringContainsString('invalid_authorization_model', $refused->getMessage());
        }
        self::assertSame(0, $this->engine->storeCount());
        self::assertSame([], $this->events->all());
    }

    public function testAnEngineThatDoesNotAnswerChangesNothing(): void
    {
        $api = $this->anApi();
        $this->engine->goDown();

        try {
            $this->configure($api->id);
            self::fail('Configured without the engine.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNull($failed->refusal);
        }
        self::assertNull($this->apis->find($api->id)?->authorization);
        self::assertSame([], $this->events->all());
    }

    public function testSwitchedOffTheStoreIsKeptAndSwitchedOnAgainItComesBack(): void
    {
        $api = $this->anApi();
        $store = $this->configure($api->id)->authorization?->store;
        self::assertNotNull($store);

        $this->disable()($api->id, false);
        $this->disable()($api->id, false);

        $off = $this->apis->find($api->id);
        self::assertFalse($off?->authorizes());
        self::assertTrue($this->engine->hasStore($store));
        self::assertCount(1, $this->events->ofType(AuthorizationDisabled::class), 'Off once.');
        self::assertFalse($this->events->ofType(AuthorizationDisabled::class)[0]->storeDeleted);

        $again = $this->configure($api->id)->authorization;
        self::assertTrue($again?->store->equals($store));
        self::assertCount(2, $this->events->ofType(AuthorizationEnabled::class));
        self::assertCount(1, $this->events->ofType(AuthorizationModelWritten::class), 'The same model.');
    }

    public function testDeletingTheStoreForgetsIt(): void
    {
        $api = $this->anApi();
        $store = $this->configure($api->id, clients: [$this->machine('reports-backend')])->authorization?->store;
        self::assertNotNull($store);

        $this->disable()($api->id, true);

        self::assertNull($this->apis->find($api->id)?->authorization);
        self::assertFalse($this->engine->hasStore($store));
        self::assertTrue($this->events->ofType(AuthorizationDisabled::class)[0]->storeDeleted ?? false);

        $this->expectException(NotFound::class);
        $this->disable()($api->id, false);
    }

    public function testAnApiThatNeverHadItHasNothingToSwitchOff(): void
    {
        $this->expectException(NotFound::class);

        $this->disable()($this->anApi()->id, false);
    }

    public function testDeletingAnApiDeletesItsStoreEvenWhenTheEngineCannotBeReached(): void
    {
        $api = $this->anApi();
        $store = $this->configure($api->id)->authorization?->store;
        self::assertNotNull($store);

        new DeleteResourceServer($this->apis, $this->events, $this->engine)($api->id);
        self::assertFalse($this->engine->hasStore($store));

        $other = $this->anApi('https://documents.test/api/');
        $this->configure($other->id);
        $this->engine->goDown();
        new DeleteResourceServer($this->apis, $this->events, $this->engine)($other->id);
        self::assertNull($this->apis->find($other->id), 'Deleted: the store, unreachable, is forgotten.');
    }

    public function testTheAuthorizationApiIsASystemApiWithItsThreeScopes(): void
    {
        $register = new RegisterAuthorizationApi(
            new SystemApiRegistration(
                $this->apis,
                new InMemoryTransactionManager(),
                new SecretGenerator(new SeededRandomSource(1)),
                new FrozenClock(),
                $this->events,
            ),
            Audience::fromString('https://management.clavia.test/access'),
        );

        $api = $register();
        $again = $register();

        self::assertTrue($api->isSystem);
        self::assertTrue($again->id->equals($api->id));
        self::assertSame('Clavia Authorization API', $api->name);
        self::assertSame('evaluate:access search:access write:relationships', $api->permissionScopes()->toString());
    }

    /**
     * @param list<ClientId> $clients
     */
    private function configure(
        ResourceServerId $id,
        string $model = DecisionEngineContract::MODEL,
        array $clients = [],
        bool $denialReasons = false,
        bool $available = true,
    ): ResourceServer {
        return new ConfigureAuthorization(
            $this->apis,
            $this->clients,
            $this->engine,
            new InMemoryTransactionManager(),
            $this->events,
            $available,
        )($id, AuthorizationModel::fromJson($model), $clients, $denialReasons);
    }

    private function disable(): DisableAuthorization
    {
        return new DisableAuthorization($this->apis, $this->engine, new InMemoryTransactionManager(), $this->events);
    }

    private function anApi(string $identifier = 'https://reports.test/api/'): ResourceServer
    {
        $api = ResourceServer::register(
            ResourceServerId::fromString('rs_' . substr(hash('sha256', $identifier), 0, 16)),
            Audience::fromString($identifier),
            'Reports API',
            [Permission::of('read:reports')],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->apis->save($api);

        return $api;
    }

    private function machine(string $id): ClientId
    {
        return $this->client($id, ClientType::Confidential, [GrantType::ClientCredentials]);
    }

    /**
     * @param list<GrantType> $grants
     */
    private function client(string $id, ClientType $type, array $grants): ClientId
    {
        $client = Client::register(
            ClientId::fromString($id),
            'A client',
            $type,
            $type === ClientType::Public ? ClientAuthMethod::None : ClientAuthMethod::ClientSecretBasic,
            $type === ClientType::Public ? null : '$hash$',
            $type === ClientType::Public ? [Url::fromString('https://reports.test/callback')] : [],
            $grants,
            in_array(GrantType::AuthorizationCode, $grants, true) ? [ResponseType::Code] : [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
        $this->clients->save($client);

        return $client->id;
    }
}
