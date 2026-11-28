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
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Clock;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\AuthorizationApiFixtures;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * AuthZEN 1.0's Access Evaluation and Access Evaluations (#138, docs/design/fine-grained-authorization.md
 * §5.2), and the decision point's metadata, against the whole application with the decision engine's
 * double. Every answer is checked against `docs/openapi/authorization-api.yaml`. What Clavia adds to the
 * context for conditions is decided by a real OpenFGA, in {@see AuthorizationApiSubjectFactsTest}.
 */
final class AuthorizationApiEvaluationTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use AuthorizationApiFixtures;

    /**
     * Folders people and applications view; documents in folders, viewed by a viewer named on them,
     * one of their editors (computed), or a viewer of their folder (inherited); edited by their owner.
     */
    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "client"},
          {"type": "team", "relations": {"member": {"this": {}}},
           "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
          {"type": "folder", "relations": {"viewer": {"this": {}}},
           "metadata": {"relations": {"viewer": {"directly_related_user_types": [
             {"type": "user"}, {"type": "client"}
           ]}}}},
          {"type": "document",
           "relations": {
             "parent": {"this": {}},
             "owner": {"this": {}},
             "editor": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}},
             "viewer": {"union": {"child": [
               {"this": {}},
               {"computedUserset": {"relation": "editor"}},
               {"tupleToUserset": {"tupleset": {"relation": "parent"}, "computedUserset": {"relation": "viewer"}}}
             ]}}
           },
           "metadata": {"relations": {
             "parent": {"directly_related_user_types": [{"type": "folder"}]},
             "owner": {"directly_related_user_types": [{"type": "user"}]},
             "editor": {"directly_related_user_types": [{"type": "user"}]},
             "viewer": {"directly_related_user_types": [{"type": "user"}, {"type": "client"}]}
           }}}
        ]}
        JSON;

    private const string EVALUATION = '/access/v1/evaluation';
    private const string EVALUATIONS = '/access/v1/evaluations';

    private FakeDecisionEngine $engine;
    private ResourceServer $api;
    private string $token;
    private string $ada;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $this->engine = new FakeDecisionEngine();
        $this->container()->setService(DecisionEngine::class, $this->engine);
        $this->container()->get(RegisterAuthorizationApi::class)();
        $this->api = $this->apiWithAuthorization('https://documents.test/api/', self::MODEL);
        $this->token = $this->tokenSpeakingFor($this->api, 'docs-backend', 'evaluate:access');
        $this->ada = $this->user()->id->value;
        $this->relate(
            'document:q3#owner@user:' . $this->ada,
            'document:q3#parent@folder:finance',
            'folder:finance#viewer@client:docs-backend',
            'document:q4#viewer@user:' . $this->ada,
        );
    }

    #[\Override]
    protected function decisionEngine(): DecisionEngine
    {
        return $this->engine;
    }

    public function testAPersonAndAnApplicationAreAnsweredThroughDirectComputedAndInheritedRelations(): void
    {
        $cases = [
            'direct' => [['user', $this->ada], 'viewer', 'q4', true],
            'computed (owner, so editor, so viewer)' => [['user', $this->ada], 'viewer', 'q3', true],
            'none' => [['user', $this->ada], 'owner', 'q4', false],
            'inherited from the folder' => [['client', 'docs-backend'], 'viewer', 'q3', true],
            'an application not named' => [['client', 'docs-backend'], 'viewer', 'q4', false],
        ];

        foreach ($cases as $case => [[$type, $id], $action, $document, $expected]) {
            $response = $this->evaluate(self::question($type, $id, $action, $document));

            self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), $case);
            self::assertSame(['decision' => $expected], self::json($response), $case);
        }
    }

    public function testAPersonDeactivatedOrUnknownIsDeniedWithoutTheEngineBeingAsked(): void
    {
        $users = $this->container()->get(UserRepository::class);
        $ada = $this->user();
        $ada->deactivate($this->container()->get(Clock::class)->now());
        $users->save($ada);
        $asked = $this->engine->questions;

        foreach (
            [
                ['user', $this->ada],
                ['user', '0b7e1c55-8f3a-4c2d-9e6b-5a4f3e2d1c0b'],
                ['user', 'not-a-uuid'],
            ] as [$type, $id]
        ) {
            self::assertSame(['decision' => false], self::json(
                $this->evaluate(self::question($type, $id, 'viewer', 'q4')),
            ));
        }
        self::assertSame($asked, $this->engine->questions, 'Nothing was sent to the engine.');
    }

    public function testADeletedApplicationIsDenied(): void
    {
        $other = $this->clientWithAToken('reports-job', 'evaluate:access');
        self::assertNotSame('', $other);
        $this->relate('document:q4#viewer@client:reports-job');
        $question = self::question('client', 'reports-job', 'viewer', 'q4');
        self::assertSame(['decision' => true], self::json($this->evaluate($question)));

        $this->container()->get(ClientRepository::class)->delete(ClientId::fromString('reports-job'));

        self::assertSame(['decision' => false], self::json($this->evaluate($question)));
    }

    public function testAQuestionThatCannotBeAskedIs400(): void
    {
        $cases = [
            'a subject neither a person nor an application' => self::question('team', 'finance', 'viewer', 'q3'),
            'a resource type the model does not declare' => ['resource' => ['type' => 'invoice', 'id' => '7']]
                + self::question('user', $this->ada, 'viewer', 'q3'),
            'a relation the type does not declare' => self::question('user', $this->ada, 'approver', 'q3'),
            'a subject-only type as the resource' => ['resource' => ['type' => 'user', 'id' => $this->ada]]
                + self::question('user', $this->ada, 'viewer', 'q3'),
            "Clavia's context" => self::question('user', $this->ada, 'viewer', 'q3') + [
                'context' => ['clavia' => ['subject' => ['roles' => ['Administrator']]]],
            ],
            'no action (AuthZEN §10.1.1)' => array_diff_key(
                self::question('user', $this->ada, 'viewer', 'q3'),
                ['action' => 0],
            ),
        ];

        foreach ($cases as $case => $question) {
            $response = $this->evaluate($question);

            self::assertSame(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                $response->getStatusCode(),
                $case . ' ' . (string) $response->getBody(),
            );
            self::assertSame('application/problem+json', $response->getHeaderLine('Content-Type'), $case);
        }
    }

    public function testMembersAuthZenDoesNotDefineAreIgnored(): void
    {
        $question = [
            'subject' => ['type' => 'user', 'id' => $this->ada, 'properties' => ['department' => 'finance']],
            'action' => ['name' => 'viewer', 'properties' => ['channel' => 'web']],
            'resource' => ['type' => 'document', 'id' => 'q4'],
            'extension' => ['anything' => true],
        ];

        self::assertSame(['decision' => true], self::json($this->evaluate($question)));
    }

    public function testABatchTakesDefaultsAndAnswersInOrderUpToWhereItsSemanticStops(): void
    {
        $batch = [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'resource' => ['type' => 'document', 'id' => 'q3'],
            'evaluations' => [
                ['action' => ['name' => 'viewer']],
                ['action' => ['name' => 'owner'], 'resource' => ['type' => 'document', 'id' => 'q4']],
                ['action' => ['name' => 'approver']],
                ['action' => ['name' => 'editor']],
            ],
        ];
        $error = [
            'status' => 400,
            'message' => "The API's authorization model gives the resource's type no such relation.",
        ];

        self::assertSame(['evaluations' => [
            ['decision' => true],
            ['decision' => false],
            ['decision' => false, 'context' => ['error' => $error]],
            ['decision' => true],
        ]], self::json($this->batch($batch)));
        self::assertSame(['evaluations' => [['decision' => true], ['decision' => false]]], self::json(
            $this->batch($batch + ['options' => ['evaluations_semantic' => 'deny_on_first_deny']]),
        ));
        self::assertSame(['evaluations' => [['decision' => true]]], self::json(
            $this->batch($batch + ['options' => ['evaluations_semantic' => 'permit_on_first_permit']]),
        ));
    }

    public function testABatchWithoutEvaluationsIsOneQuestionAndOneWithoutASubjectIsRefused(): void
    {
        $one = self::question('user', $this->ada, 'viewer', 'q4');
        self::assertSame(['decision' => true], self::json($this->batch($one)));
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->batch([
            'resource' => ['type' => 'document', 'id' => 'q3'],
            'evaluations' => [['action' => ['name' => 'viewer']]],
        ])->getStatusCode());
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->batch([
            'evaluations' => array_fill(0, 51, self::question('user', $this->ada, 'viewer', 'q4')),
        ])->getStatusCode(), 'At most fifty.');
    }

    public function testADenialSaysItsKindOnlyToAnApiThatAskedForReasons(): void
    {
        $owner = self::question('user', $this->ada, 'owner', 'q4');
        self::assertSame(['decision' => false], self::json($this->evaluate($owner)));

        $explained = $this->apiWithAuthorization('https://reports.test/api/', self::MODEL, denialReasons: true);
        $token = $this->tokenSpeakingFor($explained, 'reports-backend', 'evaluate:access');

        self::assertSame(
            ['decision' => false, 'context' => ['reason' => 'no_relation']],
            self::json($this->evaluate(self::question('user', $this->ada, 'owner', 'q4'), $token)),
        );
        self::assertSame(
            ['decision' => false, 'context' => ['reason' => 'subject_inactive']],
            self::json($this->evaluate(self::question('client', 'nobody', 'viewer', 'q4'), $token)),
        );
    }

    public function testOnlyAClientSpeakingForAnApiWithTheScopeIsAnswered(): void
    {
        $question = self::question('user', $this->ada, 'viewer', 'q4');
        $writer = $this->tokenSpeakingFor(
            $this->apiWithAuthorization('https://writers.test/api/', self::MODEL),
            'writer',
            'write:relationships',
        );
        $stranger = $this->clientWithAToken('stranger', 'evaluate:access');

        $status = fn (string $token): int => $this->evaluate($question, $token)->getStatusCode();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $status(''));
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $status('not-a-token'));
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $status($writer));
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $status($stranger));
    }

    public function testTheEngineNotAnsweringIs503NeverADecision(): void
    {
        $this->engine->goDown();

        $response = $this->evaluate(self::question('user', $this->ada, 'viewer', 'q4'));

        self::assertSame(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $response->getStatusCode());
        self::assertArrayNotHasKey('decision', self::decoded($response));
    }

    public function testTheRequestIdIsSentBack(): void
    {
        $response = $this->sendAccess(
            RequestMethodInterface::METHOD_POST,
            self::EVALUATION,
            $this->token,
            json_encode(self::question('user', $this->ada, 'viewer', 'q4'), JSON_THROW_ON_ERROR),
            ['X-Request-ID' => 'req-42'],
        );

        self::assertSame('req-42', $response->getHeaderLine('X-Request-ID'));
        self::assertSame('req-42', $this->sendAccess(
            RequestMethodInterface::METHOD_POST,
            self::EVALUATION,
            null,
            '{}',
            ['X-Request-ID' => 'req-42'],
        )->getHeaderLine('X-Request-ID'), 'On a refusal too.');
    }

    public function testTheMetadataNamesTheEndpointsThatExistAndOnlyThose(): void
    {
        $response = $this->sendAccess(RequestMethodInterface::METHOD_GET, '/.well-known/authzen-configuration', null);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
        self::assertSame([
            'policy_decision_point' => 'https://management.clavia.test',
            'access_evaluation_endpoint' => 'https://management.clavia.test/access/v1/evaluation',
            'access_evaluations_endpoint' => 'https://management.clavia.test/access/v1/evaluations',
            'search_subject_endpoint' => 'https://management.clavia.test/access/v1/search/subject',
            'search_resource_endpoint' => 'https://management.clavia.test/access/v1/search/resource',
            'search_action_endpoint' => 'https://management.clavia.test/access/v1/search/action',
            'search_max_results' => 1000,
        ], self::json($response));
        self::assertStringContainsString('max-age=', $response->getHeaderLine('Cache-Control'));

        $this->boot();
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->request(
            RequestMethodInterface::METHOD_GET,
            '/.well-known/authzen-configuration',
            [],
            self::MANAGEMENT_HOST,
        )->getStatusCode());
    }

    /** @return array<string, mixed> */
    private static function question(string $type, string $id, string $action, string $document): array
    {
        return [
            'subject' => ['type' => $type, 'id' => $id],
            'action' => ['name' => $action],
            'resource' => ['type' => 'document', 'id' => $document],
        ];
    }

    /** @param array<string, mixed> $question */
    private function evaluate(array $question, ?string $token = null): ResponseInterface
    {
        $token ??= $this->token;

        return $this->sendAccess(
            RequestMethodInterface::METHOD_POST,
            self::EVALUATION,
            $token === '' ? null : $token,
            json_encode($question, JSON_THROW_ON_ERROR),
        );
    }

    /** @param array<string, mixed> $batch */
    private function batch(array $batch): ResponseInterface
    {
        return $this->sendAccess(
            RequestMethodInterface::METHOD_POST,
            self::EVALUATIONS,
            $this->token,
            json_encode($batch, JSON_THROW_ON_ERROR),
        );
    }

    private function relate(string ...$tuples): void
    {
        $settings = $this->api->authorization;
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
}
