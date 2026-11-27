<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\RegisterManagementApiCommand;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use stdClass;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * `GET|PUT|DELETE /api/v1/resource-servers/{id}/authorization` (#136,
 * docs/design/fine-grained-authorization.md §5.1), against the whole application, with the decision
 * engine's double in OpenFGA's place.
 */
final class ManagementResourceServerAuthorizationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string PATH = '/api/v1/resource-servers/%s/authorization';

    private FakeDecisionEngine $engine;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $this->engine = new FakeDecisionEngine();
        $this->container()->setService(DecisionEngine::class, $this->engine);
    }

    public function testAnApiIsGivenAStoreItsModelAndTheClientsSpeakingForIt(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', ['read:reports']);
        $this->speakingClient('reports-backend');

        $response = $this->put($api, ['clients' => ['reports-backend'], 'denial_reasons' => true]);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        $settings = self::document($response);
        self::assertTrue($settings['enabled']);
        self::assertSame(['reports-backend'], $settings['clients']);
        self::assertTrue($settings['denial_reasons']);
        self::assertIsString($settings['store_id']);
        self::assertTrue($this->engine->hasStore(StoreId::fromString($settings['store_id'])));
        // The model comes back as it was sent: `"this": {}` an object still.
        self::assertStringContainsString('"this":{}', (string) $response->getBody());
        $answer = json_decode((string) $response->getBody(), false, 64, JSON_THROW_ON_ERROR);
        self::assertInstanceOf(stdClass::class, $answer);
        self::assertSame(
            json_encode(json_decode(DecisionEngineContract::MODEL), JSON_THROW_ON_ERROR),
            json_encode($answer->model, JSON_THROW_ON_ERROR),
        );

        $read = $this->api(RequestMethodInterface::METHOD_GET, sprintf(self::PATH, $api->id->value));
        self::assertSame(StatusCodeInterface::STATUS_OK, $read->getStatusCode());
        self::assertSame($settings, self::document($read));

        foreach ([AuditEventType::AuthorizationEnabled, AuditEventType::AuthorizationModelWritten] as $type) {
            self::assertSame(1, $this->recorded($type), $type->value);
        }
        // The model's id in the trail, never its content.
        $details = (string) TestStorage::database()->fetchValue(
            'SELECT details::text FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::AuthorizationModelWritten->value],
        );
        self::assertStringContainsString((string) $settings['model_id'], $details);
        self::assertStringNotContainsString('type_definitions', $details);
    }

    public function testAnApiWithoutItIsNotFound(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);

        foreach ([RequestMethodInterface::METHOD_GET, RequestMethodInterface::METHOD_DELETE] as $method) {
            self::assertSame(
                StatusCodeInterface::STATUS_NOT_FOUND,
                $this->api($method, sprintf(self::PATH, $api->id->value))->getStatusCode(),
            );
        }
    }

    public function testEachRefusalPointsAtWhatIsAtFaultAndLeavesNothing(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        $this->confidentialClient();
        $this->speakingClient('reports-backend');
        $roleComputed = '{"schema_version": "1.1", "type_definitions": [{"type": "user"}, {"type": "role", '
            . '"relations": {"member": {"computedUserset": {"relation": "admin"}}, "admin": {"this": {}}}, '
            . '"metadata": {"relations": {"admin": {"directly_related_user_types": [{"type": "user"}]}}}}]}';
        $incoherent = '{"schema_version": "1.1", "type_definitions": [{"type": "user"}, {"type": "document", '
            . '"relations": {"viewer": {"computedUserset": {"relation": "editor"}}}}]}';

        foreach (
            [
            '/model' => [$roleComputed, []],
            '/model ' => [$incoherent, []],
            '/clients/1' => [DecisionEngineContract::MODEL, ['reports-backend', 'nobody']],
            '/clients/0' => [DecisionEngineContract::MODEL, [self::TEST_CLIENT_ID]],
            '/clients' => [DecisionEngineContract::MODEL, ['reports-backend', 'reports-backend']],
            ] as $pointer => [$model, $clients]
        ) {
            $response = $this->put($api, ['clients' => $clients], $model);

            self::assertSame(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                $response->getStatusCode(),
                (string) $response->getBody(),
            );
            $errors = self::document($response)['errors'];
            self::assertIsArray($errors);
            self::assertIsArray($errors[0]);
            self::assertSame(trim($pointer), $errors[0]['pointer']);
        }
        $refusal = (string) $this->put($api, [], $incoherent)->getBody();
        self::assertStringContainsString('invalid_authorization_model', $refusal);
        self::assertSame(0, $this->engine->storeCount());
        self::assertNull($this->container()->get(ResourceServerRepository::class)->find($api->id)?->authorization);
    }

    public function testAClientSpeaksForOneApiAtMost(): void
    {
        $this->adminToken();
        $this->speakingClient('shared-backend');
        $first = $this->anApi('https://reports.test/api/', []);
        $second = $this->anApi('https://documents.test/api/', []);

        $accepted = $this->put($first, ['clients' => ['shared-backend']]);
        self::assertSame(StatusCodeInterface::STATUS_OK, $accepted->getStatusCode());
        $refused = $this->put($second, ['clients' => ['shared-backend']]);

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $refused->getStatusCode());
        self::assertStringNotContainsString('shared-backend', (string) $refused->getBody());
        self::assertSame(1, $this->engine->storeCount(), 'The store made for the second is deleted again.');
    }

    public function testASystemApiAndAServerWithoutAnEngineAreConflicts(): void
    {
        $this->adminToken();

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $this->put($this->managementApi(), [])->getStatusCode());

        $this->boot();
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $this->put($api, [])->getStatusCode());
    }

    public function testAnEngineThatDoesNotAnswerIsA503AndChangesNothing(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        $this->engine->goDown();

        $response = $this->put($api, []);

        self::assertSame(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $response->getStatusCode());
        self::assertSame(0, $this->recorded(AuditEventType::AuthorizationEnabled));

        $this->engine->comeBack();
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->put($api, [])->getStatusCode());
        $this->engine->goDown();
        self::assertSame(
            StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
            $this->statusOf(
                RequestMethodInterface::METHOD_DELETE,
                sprintf(self::PATH, $api->id->value),
                ['confirm' => 'delete'],
            ),
        );
        // The deletion rolled back: the store is still known, and still on.
        $read = $this->api(RequestMethodInterface::METHOD_GET, sprintf(self::PATH, $api->id->value));
        self::assertTrue(self::document($read)['enabled']);
    }

    public function testSwitchedOffTheStoreIsKeptAndDeletedOnlyOnConfirmation(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        $store = self::document($this->put($api, []))['store_id'];
        self::assertIsString($store);
        $path = sprintf(self::PATH, $api->id->value);

        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $this->statusOf(RequestMethodInterface::METHOD_DELETE, $path),
        );
        $off = self::document($this->api(RequestMethodInterface::METHOD_GET, $path));
        self::assertFalse($off['enabled']);
        self::assertSame($store, $off['store_id']);
        self::assertTrue($this->engine->hasStore(StoreId::fromString($store)));

        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $this->api(RequestMethodInterface::METHOD_DELETE, $path, query: ['confirm' => 'delete'])->getStatusCode(),
        );
        self::assertFalse($this->engine->hasStore(StoreId::fromString($store)));
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->statusOf(RequestMethodInterface::METHOD_GET, $path),
        );
        self::assertSame(2, $this->recorded(AuditEventType::AuthorizationDisabled));
    }

    public function testDeletingTheApiDeletesItsStore(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        $store = self::document($this->put($api, []))['store_id'];
        self::assertIsString($store);

        $deleted = $this->api(RequestMethodInterface::METHOD_DELETE, '/api/v1/resource-servers/' . $api->id->value);

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $deleted->getStatusCode());
        self::assertFalse($this->engine->hasStore(StoreId::fromString($store)));
    }

    public function testDeletingAClientStopsItSpeakingForTheApi(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://reports.test/api/', []);
        $this->speakingClient('reports-backend');
        $this->put($api, ['clients' => ['reports-backend']]);

        $this->container()->get(ClientRepository::class)->delete(ClientId::fromString('reports-backend'));

        $path = sprintf(self::PATH, $api->id->value);
        $settings = self::document($this->api(RequestMethodInterface::METHOD_GET, $path));
        self::assertSame([], $settings['clients']);
    }

    public function testReadingNeedsReadAndChangingNeedsUpdate(): void
    {
        $this->adminToken(['read:resource_servers']);
        $api = $this->anApi('https://reports.test/api/', []);
        $path = sprintf(self::PATH, $api->id->value);

        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->statusOf(RequestMethodInterface::METHOD_GET, $path),
        );
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $this->put($api, [])->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->statusOf(RequestMethodInterface::METHOD_DELETE, $path),
        );
    }

    public function testRegisteringTheManagementApiRegistersTheAuthorizationApiWhenItIsOn(): void
    {
        $tester = new CommandTester($this->container()->get(RegisterManagementApiCommand::class));
        $tester->execute([]);

        self::assertStringContainsString(
            'Authorization API registered as https://management.clavia.test/access',
            $tester->getDisplay(),
        );
        $api = $this->container()->get(ResourceServerRepository::class)
            ->findByIdentifier(Audience::fromString('https://management.clavia.test/access'));
        self::assertNotNull($api);
        self::assertTrue($api->isSystem);
        self::assertSame('evaluate:access search:access write:relationships', $api->permissionScopes()->toString());

        $this->boot();
        $off = new CommandTester($this->container()->get(RegisterManagementApiCommand::class));
        $off->execute([]);
        self::assertStringNotContainsString('Authorization API', $off->getDisplay());
    }

    /**
     * @param array<string, mixed> $fields Beside the model.
     */
    private function put(
        ResourceServer $api,
        array $fields,
        string $model = DecisionEngineContract::MODEL,
    ): ResponseInterface {
        // Sent as text, so the model's empty objects reach the server as objects.
        $body = json_encode($fields + ['model' => '__MODEL__'], JSON_THROW_ON_ERROR);
        $body = str_replace('"__MODEL__"', $model, $body);

        return $this->api(
            RequestMethodInterface::METHOD_PUT,
            sprintf(self::PATH, $api->id->value),
            rawBody: $body,
        );
    }

    /** @param array<string, string> $query */
    private function statusOf(string $method, string $path, array $query = []): int
    {
        return $this->api($method, $path, query: $query)->getStatusCode();
    }

    private function speakingClient(string $id): Client
    {
        $client = Client::register(
            ClientId::fromString($id),
            'Reports backend',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            '$hash$',
            [],
            [GrantType::ClientCredentials],
            [],
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(ClientRepository::class)->save($client);

        return $client;
    }

    private function recorded(AuditEventType $type): int
    {
        return (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => $type->value],
        );
    }
}
