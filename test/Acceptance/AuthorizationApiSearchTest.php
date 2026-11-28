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
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
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
 * AuthZEN's Subject, Resource and Action Search (#140, docs/design/fine-grained-authorization.md §5.5)
 * against the whole application with the decision engine's double, every answer checked against
 * `docs/openapi/authorization-api.yaml`. Conditions over Clavia's facts are a real OpenFGA's to decide,
 * in {@see AuthorizationApiSubjectFactsTest}.
 */
final class AuthorizationApiSearchTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use AuthorizationApiFixtures;

    /** Folders, and documents in them: viewed by a viewer, an editor (an owner is one), or a viewer of their folder. */
    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "client"},
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

    private const string BOB = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a02';
    private const string CY = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a03';
    private const string NOBODY = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a09';

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
        $this->token = $this->tokenSpeakingFor($this->api, 'docs-backend', 'search:access');
        $this->ada = $this->user()->id->value;
        $this->person(self::BOB, 'bob@example.com');
        $this->person(self::CY, 'cy@example.com', active: false);
        $this->relate(
            'document:q3#owner@user:' . $this->ada,
            'document:q3#parent@folder:finance',
            'folder:finance#viewer@user:' . self::BOB,
            'folder:finance#viewer@user:' . self::CY,
            'folder:finance#viewer@user:' . self::NOBODY,
            'folder:finance#viewer@client:docs-backend',
            'folder:finance#viewer@client:deleted-job',
            'document:q4#viewer@user:' . $this->ada,
            'document:q5#viewer@user:' . self::BOB,
        );
    }

    #[\Override]
    protected function decisionEngine(): DecisionEngine
    {
        return $this->engine;
    }

    public function testWhoMayViewAResourceLeavesOutTheGoneAndTheDeactivated(): void
    {
        $people = $this->search('subject', [
            'subject' => ['type' => 'user'],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document', 'id' => 'q3'],
        ]);
        $applications = $this->search('subject', [
            'subject' => ['type' => 'client', 'id' => 'ignored'],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document', 'id' => 'q3'],
        ]);

        $expected = [self::BOB, $this->ada];
        sort($expected);
        self::assertSame(
            array_map(static fn (string $id): array => ['type' => 'user', 'id' => $id], $expected),
            $people['results'],
            'Through the folder and as owner; Cy deactivated and an unknown account left out.',
        );
        self::assertSame(['next_token' => '', 'count' => 2], $people['page']);
        self::assertSame([['type' => 'client', 'id' => 'docs-backend']], $applications['results']);
    }

    public function testWhatASubjectMayViewAndDo(): void
    {
        $resources = $this->search('resource', [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document', 'id' => 'ignored'],
        ]);
        $actions = $this->search('action', [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'resource' => ['type' => 'document', 'id' => 'q3'],
        ]);

        self::assertSame(
            [['type' => 'document', 'id' => 'q3'], ['type' => 'document', 'id' => 'q4']],
            $resources['results'],
        );
        self::assertSame(
            [['name' => 'owner'], ['name' => 'editor'], ['name' => 'viewer']],
            $actions['results'],
            'In the order the model declares them.',
        );
    }

    public function testASubjectClaviaDoesNotKnowHasNothingAndTheEngineIsNotAsked(): void
    {
        $asked = $this->engine->questions;

        foreach ([self::CY, self::NOBODY] as $id) {
            self::assertSame([], $this->search('resource', [
                'subject' => ['type' => 'user', 'id' => $id],
                'action' => ['name' => 'viewer'],
                'resource' => ['type' => 'document'],
            ])['results']);
            self::assertSame([], $this->search('action', [
                'subject' => ['type' => 'user', 'id' => $id],
                'resource' => ['type' => 'document', 'id' => 'q3'],
            ])['results']);
        }
        self::assertSame($asked, $this->engine->questions);
    }

    public function testPagesFollowTheTokenAndTheTokenBelongsToItsSearch(): void
    {
        $search = [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'document'],
            'page' => ['limit' => 1],
        ];
        $first = $this->search('resource', $search);
        self::assertSame([['type' => 'document', 'id' => 'q3']], $first['results']);
        $page = $first['page'];
        self::assertIsArray($page);
        self::assertSame(1, $page['count']);
        self::assertIsString($page['next_token']);
        self::assertNotSame('', $page['next_token']);

        $search['page']['token'] = $page['next_token'];
        $second = $this->search('resource', $search);
        self::assertSame([['type' => 'document', 'id' => 'q4']], $second['results']);
        self::assertSame(['next_token' => '', 'count' => 1], $second['page'], 'The last page.');

        // The rest of the search must stay as it was (AuthZEN §8.2).
        $changed = $search;
        $changed['action']['name'] = 'editor';
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->send('resource', $changed)->getStatusCode());
        $search['page']['token'] = 'not-a-token';
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $this->send('resource', $search)->getStatusCode());
    }

    public function testASearchThatCannotBeAskedIs400(): void
    {
        $cases = [
            'a subject neither a person nor an application' => ['subject', [
                'subject' => ['type' => 'folder'],
                'action' => ['name' => 'viewer'],
                'resource' => ['type' => 'document', 'id' => 'q3'],
            ]],
            'a relation the type lacks' => ['resource', [
                'subject' => ['type' => 'user', 'id' => $this->ada],
                'action' => ['name' => 'approver'],
                'resource' => ['type' => 'document'],
            ]],
            "Clavia's context" => ['action', [
                'subject' => ['type' => 'user', 'id' => $this->ada],
                'resource' => ['type' => 'document', 'id' => 'q3'],
                'context' => ['clavia' => []],
            ]],
            'no resource type' => ['resource', [
                'subject' => ['type' => 'user', 'id' => $this->ada],
                'action' => ['name' => 'viewer'],
                'resource' => ['id' => 'q3'],
            ]],
        ];

        foreach ($cases as $case => [$kind, $search]) {
            self::assertSame(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                $this->send($kind, $search)->getStatusCode(),
                $case,
            );
        }
    }

    public function testSearchingTakesItsOwnScope(): void
    {
        $evaluator = $this->tokenSpeakingFor(
            $this->apiWithAuthorization('https://evaluators.test/api/', self::MODEL),
            'evaluator',
            'evaluate:access',
        );

        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $this->send('action', [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'resource' => ['type' => 'document', 'id' => 'q3'],
        ], $evaluator)->getStatusCode());
    }

    public function testTheMetadataNamesTheSearchesAndTheirCap(): void
    {
        $metadata = self::json($this->sendAccess(
            RequestMethodInterface::METHOD_GET,
            '/.well-known/authzen-configuration',
            null,
        ));

        foreach (['subject', 'resource', 'action'] as $kind) {
            self::assertSame(
                'https://management.clavia.test/access/v1/search/' . $kind,
                $metadata['search_' . $kind . '_endpoint'] ?? null,
            );
        }
        self::assertSame(1000, $metadata['search_max_results'] ?? null);
    }

    /**
     * @param array<string, mixed> $search
     *
     * @return array<array-key, mixed>
     */
    private function search(string $kind, array $search): array
    {
        $response = $this->send($kind, $search);
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());

        return self::json($response);
    }

    /** @param array<string, mixed> $search */
    private function send(string $kind, array $search, ?string $token = null): ResponseInterface
    {
        return $this->sendAccess(
            RequestMethodInterface::METHOD_POST,
            '/access/v1/search/' . $kind,
            $token ?? $this->token,
            json_encode($search, JSON_THROW_ON_ERROR),
        );
    }

    private function person(string $id, string $email, bool $active = true): void
    {
        $clock = $this->container()->get(Clock::class);
        $user = User::register(UserId::fromString($id), $email, null, $clock->now());
        if (! $active) {
            $user->deactivate($clock->now());
        }
        $this->container()->get(UserRepository::class)->save($user);
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
