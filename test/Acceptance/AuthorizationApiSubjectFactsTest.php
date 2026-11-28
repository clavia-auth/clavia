<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Management\Provisioning\RegisterAuthorizationApi;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\Condition;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Identity\AppMetadata;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\GrantedPermission;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Scope;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\AuthorizationApiFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestEnvironment;
use Fig\Http\Message\RequestMethodInterface;

/**
 * Clavia as an information point (#138, docs/design/fine-grained-authorization.md §2, "Context and
 * conditions"): what it knows of the subject, `context.clavia.subject`, decided by a real OpenFGA's
 * conditions, both ways. Skipped when `CLAVIA_TEST_FGA_URL` names no OpenFGA: the double does not
 * evaluate conditions.
 */
final class AuthorizationApiSubjectFactsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use AuthorizationApiFixtures;

    /**
     * A document viewed by a person of its department, by an auditor (a role of this API), or by a
     * first-party application: three conditions over Clavia's facts, read through `clavia`, `map<any>`.
     */
    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "client"},
          {"type": "document", "relations": {"viewer": {"this": {}}},
           "metadata": {"relations": {"viewer": {"directly_related_user_types": [
             {"type": "user", "condition": "same_department"},
             {"type": "user", "condition": "auditor"},
             {"type": "client", "condition": "first_party"}
           ]}}}}
        ],
        "conditions": {
          "same_department": {"name": "same_department",
            "expression": "clavia.subject.app_metadata.department == department",
            "parameters": {"clavia": {"type_name": "TYPE_NAME_MAP",
              "generic_types": [{"type_name": "TYPE_NAME_ANY"}]},
                           "department": {"type_name": "TYPE_NAME_STRING"}}},
          "auditor": {"name": "auditor",
            "expression": "'Auditors' in clavia.subject.roles",
            "parameters": {"clavia": {"type_name": "TYPE_NAME_MAP",
              "generic_types": [{"type_name": "TYPE_NAME_ANY"}]}}},
          "first_party": {"name": "first_party",
            "expression": "clavia.subject.first_party == true",
            "parameters": {"clavia": {"type_name": "TYPE_NAME_MAP",
              "generic_types": [{"type_name": "TYPE_NAME_ANY"}]}}}
        }}
        JSON;

    private const string EVALUATION = '/access/v1/evaluation';
    private const string EVALUATIONS = '/access/v1/evaluations';

    /** @var list<StoreId> */
    private array $stores = [];

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $url = TestEnvironment::fgaUrl();
        if ($url === null) {
            self::markTestSkipped('CLAVIA_TEST_FGA_URL names no OpenFGA to decide conditions.');
        }
        $this->boot(['CLAVIA_FGA_URL' => $url, 'CLAVIA_FGA_API_KEY' => TestEnvironment::fgaApiKey()]);
        $this->container()->get(RegisterAuthorizationApi::class)();
    }

    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->stores as $store) {
            try {
                $this->decisionEngine()->deleteStore($store);
            } catch (DecisionEngineFailed) {
                // Gone already.
            }
        }
        parent::tearDown();
    }

    #[\Override]
    protected function decisionEngine(): DecisionEngine
    {
        return $this->container()->get(DecisionEngine::class);
    }

    public function testAConditionOnAPersonsApplicationMetadataDecidesBothWays(): void
    {
        $api = $this->api('https://documents.test/api/');
        $token = $this->tokenSpeakingFor($api, 'docs-backend', 'evaluate:access');
        $ada = $this->user();
        $this->relate($api, 'document:q3', 'user:' . $ada->id->value, Condition::of('same_department', [
            'department' => 'finance',
        ]));

        $this->metadata('{"department": "finance"}');
        self::assertTrue($this->decision($token, 'user', $ada->id->value));

        $this->metadata('{"department": "sales"}');
        self::assertFalse($this->decision($token, 'user', $ada->id->value));

        // No department at all: the condition cannot be evaluated, and the question alone is denied.
        $this->metadata('{"level": 3}');
        self::assertFalse($this->decision($token, 'user', $ada->id->value));
        $batch = $this->sendAccess(RequestMethodInterface::METHOD_POST, self::EVALUATIONS, $token, json_encode([
            'subject' => ['type' => 'user', 'id' => $ada->id->value],
            'evaluations' => [
                ['action' => ['name' => 'viewer'], 'resource' => ['type' => 'document', 'id' => 'q3']],
                ['action' => ['name' => 'viewer'], 'resource' => ['type' => 'document', 'id' => 'q9']],
            ],
        ], JSON_THROW_ON_ERROR));
        self::assertSame(200, $batch->getStatusCode(), (string) $batch->getBody());
        self::assertSame(['evaluations' => [['decision' => false], ['decision' => false]]], self::decoded($batch));
    }

    public function testRolesAreTheApisOwnOnly(): void
    {
        $api = $this->api('https://documents.test/api/');
        $other = $this->anApi('https://elsewhere.test/api/', ['read']);
        $token = $this->tokenSpeakingFor($api, 'docs-backend', 'evaluate:access');
        $ada = $this->user()->id;
        $this->relate($api, 'document:q3', 'user:' . $ada->value, Condition::of('auditor'));
        $roles = $this->container()->get(RoleRepository::class);
        $now = $this->container()->get(Clock::class)->now();
        // Auditors elsewhere: not this API's, so not in what it is told.
        $auditors = Role::define(RoleId::fromString('rol_AUDITORSAUDITOR1'), 'Auditors', '', [
            new GrantedPermission($other->id, Scope::fromString('read')),
        ], $now);
        $roles->save($auditors);
        $roles->assign($auditors->id, $ada, $now);

        self::assertFalse($this->decision($token, 'user', $ada->value));

        $roles->save($auditors->granting([new GrantedPermission($api->id, Scope::fromString('read'))]));
        self::assertTrue($this->decision($token, 'user', $ada->value));
    }

    public function testAnApplicationsFactsAreClaviasToo(): void
    {
        $api = $this->api('https://documents.test/api/');
        $token = $this->tokenSpeakingFor($api, 'docs-backend', 'evaluate:access');
        $this->relate($api, 'document:q3', 'client:docs-backend', Condition::of('first_party'));

        self::assertTrue($this->decision($token, 'client', 'docs-backend'));
        // Whatever the API says of it: `context.clavia` is refused.
        $forged = $this->sendAccess(RequestMethodInterface::METHOD_POST, self::EVALUATION, $token, json_encode([
            'subject' => ['type' => 'client', 'id' => 'docs-backend'],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document', 'id' => 'q3'],
            'context' => ['clavia' => ['subject' => ['first_party' => true]]],
        ], JSON_THROW_ON_ERROR));
        self::assertSame(400, $forged->getStatusCode());
    }

    private function api(string $identifier): ResourceServer
    {
        $api = $this->apiWithAuthorization($identifier, self::MODEL);
        $this->stores[] = $this->storeOf($api);

        return $api;
    }

    private function relate(ResourceServer $api, string $object, string $subject, Condition $condition): void
    {
        $settings = $this->container()->get(ResourceServerRepository::class)
            ->find($api->id)?->authorization;
        self::assertNotNull($settings);
        $this->decisionEngine()->write($settings->store, $settings->modelId, [Tuple::of(
            ObjectRef::fromString($object),
            Relation::fromString('viewer'),
            SubjectRef::fromString($subject),
            $condition,
        )]);
    }

    private function metadata(string $json): void
    {
        $users = $this->container()->get(UserRepository::class);
        $ada = $this->user();
        $ada->changeAppMetadata(AppMetadata::fromJson($json), $this->container()->get(Clock::class)->now());
        $users->save($ada);
    }

    private function decision(string $token, string $type, string $id): bool
    {
        $response = $this->sendAccess(RequestMethodInterface::METHOD_POST, self::EVALUATION, $token, json_encode([
            'subject' => ['type' => $type, 'id' => $id],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document', 'id' => 'q3'],
        ], JSON_THROW_ON_ERROR));
        self::assertSame(200, $response->getStatusCode(), (string) $response->getBody());

        return self::decoded($response)['decision'] === true;
    }
}
