<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\ResyncStoreCommand;
use Clavia\Adapter\Primary\Cli\SyncIdentityFeedCommand;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The identity feed (#137, docs/design/fine-grained-authorization.md §5.4), against the whole
 * application with the decision engine's double in OpenFGA's place: roles given and taken through
 * the Management API reach the API's store after the response, survive the engine being down, and
 * `fga:resync` repairs a drift.
 */
final class FineGrainedIdentityFeedTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "role", "relations": {"member": {"this": {}}},
           "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
          {"type": "document", "relations": {"viewer": {"this": {}}},
           "metadata": {"relations": {"viewer": {"directly_related_user_types": [
             {"type": "user"}, {"type": "role", "relation": "member"}
           ]}}}}
        ]}
        JSON;

    private FakeDecisionEngine $engine;
    private FrozenClock $clock;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $this->clock = $this->freezeClock('2026-11-28T10:00:00Z');
        $this->engine = new FakeDecisionEngine();
        $this->container()->setService(DecisionEngine::class, $this->engine);
    }

    public function testARoleGivenAndTakenReachesAndLeavesTheStoreAfterTheResponse(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://documents.test/api/', ['read:documents']);
        $role = $this->aRole($api, 'read:documents');
        $user = $this->user()->id->value;
        // Held before authorization is on: switching it on writes the members already there.
        $this->assign($role, $user);
        $this->enable($api);

        self::assertSame(["role:$role#member@user:$user"], $this->relationshipsIn($api));

        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->api(
            RequestMethodInterface::METHOD_DELETE,
            "/api/v1/roles/$role/users/$user",
        )->getStatusCode());

        self::assertSame([], $this->relationshipsIn($api));
        self::assertSame(0, self::waiting());
    }

    public function testAChangeTheEngineDidNotTakeWaitsInTheOutboxUntilFgaSync(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://documents.test/api/', ['read:documents']);
        $this->enable($api);
        $role = $this->aRole($api, 'read:documents');
        $user = $this->user()->id->value;

        $this->engine->goDown();
        $this->assign($role, $user);

        self::assertSame(1, self::waiting(), 'Committed with the change, kept when the send failed.');
        self::assertSame(1, (int) TestStorage::database()->fetchValue('SELECT attempts FROM fga_outbox'));

        $this->engine->comeBack();
        [, $early] = $this->runCommand(SyncIdentityFeedCommand::class);
        self::assertStringContainsString('Sent 0', $early, 'Not due yet.');
        $this->clock->advance(5);
        [$status, $output] = $this->runCommand(SyncIdentityFeedCommand::class);

        self::assertSame(Command::SUCCESS, $status);
        self::assertStringContainsString('Sent 1 identity change(s); 0 could not be sent', $output);
        self::assertSame(["role:$role#member@user:$user"], $this->relationshipsIn($api));
        self::assertSame(0, self::waiting());
    }

    public function testFgaResyncRepairsADrift(): void
    {
        $this->adminToken();
        $api = $this->anApi('https://documents.test/api/', ['read:documents']);
        $this->enable($api);
        $role = $this->aRole($api, 'read:documents');
        $user = $this->user()->id->value;
        $this->assign($role, $user);
        // The store drifts: a member nobody gave the role to, and the real one lost.
        $stranger = '0b7e1c55-8f3a-4c2d-9e6b-5a4f3e2d1c0b';
        $settings = $this->settingsOf($api);
        $this->engine->write($settings->store, $settings->modelId, [self::membership($role, $stranger)], [
            self::membership($role, $user),
        ]);

        [$status, $output] = $this->runCommand(ResyncStoreCommand::class, ['api' => 'https://documents.test/api/']);

        self::assertSame(Command::SUCCESS, $status, $output);
        self::assertStringContainsString('1 role membership(s) written, 1 deleted', $output);
        self::assertSame(["role:$role#member@user:$user"], $this->relationshipsIn($api));

        [$again] = $this->runCommand(ResyncStoreCommand::class, ['api' => 'https://nothing.test/api/']);
        self::assertSame(Command::FAILURE, $again, 'An API without authorization is refused.');
    }

    private function enable(ResourceServer $api): void
    {
        $body = str_replace(
            '"__MODEL__"',
            self::MODEL,
            json_encode(['model' => '__MODEL__', 'clients' => [], 'denial_reasons' => false], JSON_THROW_ON_ERROR),
        );
        $response = $this->api(
            RequestMethodInterface::METHOD_PUT,
            sprintf('/api/v1/resource-servers/%s/authorization', $api->id->value),
            rawBody: $body,
        );
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
    }

    private function aRole(ResourceServer $api, string $permission): string
    {
        $response = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/roles', [
            'name' => 'Editors',
            'description' => 'Edit documents.',
            'permissions' => [['resource_server_id' => $api->id->value, 'value' => $permission]],
        ]);
        self::assertSame(
            StatusCodeInterface::STATUS_CREATED,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );

        return (string) self::document($response)['id'];
    }

    private function assign(string $role, string $user): void
    {
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $this->api(
            RequestMethodInterface::METHOD_POST,
            "/api/v1/roles/$role/users",
            ['user_ids' => [$user]],
        )->getStatusCode());
    }

    /** @return list<string> */
    private function relationshipsIn(ResourceServer $api): array
    {
        return $this->engine->relationshipsIn($this->settingsOf($api)->store);
    }

    private function settingsOf(ResourceServer $api): AuthorizationSettings
    {
        $settings = $this->container()->get(ResourceServerRepository::class)->find($api->id)?->authorization;
        self::assertNotNull($settings);

        return $settings;
    }

    private static function membership(string $role, string $user): Tuple
    {
        return Tuple::of(
            ObjectRef::fromString("role:$role"),
            Relation::fromString('member'),
            SubjectRef::fromString("user:$user"),
        );
    }

    private static function waiting(): int
    {
        return (int) TestStorage::database()->fetchValue('SELECT count(*) FROM fga_outbox');
    }

    /**
     * @param class-string<Command> $command
     * @param array<string, string> $arguments
     *
     * @return array{int, string}
     */
    private function runCommand(string $command, array $arguments = []): array
    {
        /** @var Command $instance */
        $instance = $this->container()->get($command);
        $tester = new CommandTester($instance);
        $status = $tester->execute($arguments);

        return [$status, $tester->getDisplay(true)];
    }
}
