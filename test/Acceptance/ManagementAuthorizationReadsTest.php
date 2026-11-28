<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Application\Port\DecisionEngine;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\AuthorizationApiFixtures;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An operator's reads of an API's authorization (#242, docs/design/fine-grained-authorization.md §5.6):
 * its model versions, an object's relationships, and a decision tried, through the Management API,
 * from the store of the API in the path and no other.
 */
final class ManagementAuthorizationReadsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use ManagementFixtures;
    use AuthorizationApiFixtures;

    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "client"},
          {"type": "role", "relations": {"member": {"this": {}}},
           "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
          {"type": "report", "relations": {
             "owner": {"this": {}},
             "viewer": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}}
           },
           "metadata": {"relations": {
             "owner": {"directly_related_user_types": [{"type": "user"}]},
             "viewer": {"directly_related_user_types": [{"type": "user"}, {"type": "role", "relation": "member"}]}
           }}}
        ]}
        JSON;

    /** Another API's model: invoices, which the Reports API knows nothing of. */
    private const string OTHER_MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "invoice", "relations": {"viewer": {"this": {}}},
           "metadata": {"relations": {"viewer": {"directly_related_user_types": [{"type": "user"}]}}}}
        ]}
        JSON;

    private const string PATH = '/api/v1/resource-servers/%s/authorization/%s';

    private FakeDecisionEngine $engine;
    private ResourceServer $reports;
    private ResourceServer $invoices;
    private string $ada;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $this->engine = new FakeDecisionEngine();
        $this->container()->setService(DecisionEngine::class, $this->engine);
        $this->reports = $this->apiWithAuthorization('https://reports.test/api/', self::MODEL);
        $this->invoices = $this->apiWithAuthorization('https://invoices.test/api/', self::OTHER_MODEL);
        $this->ada = $this->user()->id->value;
        $this->relate($this->reports, 'report:q3#owner@user:' . $this->ada, 'report:q3#viewer@role:finance#member');
        $this->relate($this->invoices, 'invoice:q3#viewer@user:' . $this->ada);
    }

    #[\Override]
    protected function decisionEngine(): DecisionEngine
    {
        return $this->engine;
    }

    public function testTheModelVersionsAreReadNewestFirstThePageInForceMarked(): void
    {
        $this->adminToken();
        $settings = $this->reports->authorization;
        self::assertNotNull($settings);
        $later = [
            $this->engine->writeModel($settings->store, AuthorizationModel::fromJson(self::MODEL))->value,
            $this->engine->writeModel($settings->store, AuthorizationModel::fromJson(self::MODEL))->value,
        ];

        $first = $this->read($this->reports, 'models', ['page_size' => '2']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $first->getStatusCode(), (string) $first->getBody());
        $page = self::document($first);
        self::assertSame(array_reverse($later), array_column(self::items($page), 'id'));
        self::assertSame([false, false], array_column(self::items($page), 'in_force'));
        // The model as the engine keeps it: `"this": {}` an object still.
        self::assertStringContainsString('"this":{}', (string) $first->getBody());
        self::assertIsString($page['next_page_token']);

        $second = self::document($this->read($this->reports, 'models', [
            'page_size' => '2',
            'page_token' => $page['next_page_token'],
        ]));
        self::assertSame([$settings->modelId->value], array_column(self::items($second), 'id'));
        self::assertSame([true], array_column(self::items($second), 'in_force'));
        self::assertArrayNotHasKey('next_page_token', $second);

        self::assertSame(
            StatusCodeInterface::STATUS_BAD_REQUEST,
            $this->read($this->reports, 'models', ['page_token' => 'bm90LWEtdG9rZW4'])->getStatusCode(),
        );
    }

    public function testAnObjectsRelationshipsAreReadFromTheApiInThePathAlone(): void
    {
        $this->adminToken();

        $response = $this->read($this->reports, 'relationships', ['object' => 'report:q3']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        self::assertSame([
            'items' => [
                [
                    'resource' => ['type' => 'report', 'id' => 'q3'],
                    'relation' => 'owner',
                    'subject' => ['type' => 'user', 'id' => $this->ada],
                ],
                [
                    'resource' => ['type' => 'report', 'id' => 'q3'],
                    'relation' => 'viewer',
                    'subject' => ['type' => 'role', 'id' => 'finance', 'relation' => 'member'],
                ],
            ],
        ], self::document($response));

        // Another API's type, Clavia's own, and a token no page gave.
        foreach (
            [
                [$this->reports, ['object' => 'invoice:q3'], StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY],
                [$this->reports, ['object' => 'role:finance'], StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY],
                [
                    $this->reports,
                    ['object' => 'report:q3', 'page_token' => 'bm90LWEtdG9rZW4'],
                    StatusCodeInterface::STATUS_BAD_REQUEST,
                ],
            ] as [$api, $query, $status]
        ) {
            $refused = $this->read($api, 'relationships', $query);
            self::assertSame($status, $refused->getStatusCode(), (string) $refused->getBody());
            self::assertSame(
                isset($query['page_token']) ? 'page_token' : 'object',
                self::document($refused)['errors'][0]['parameter'] ?? null,
            );
        }
        self::assertCount(
            1,
            self::items(self::document($this->read($this->invoices, 'relationships', ['object' => 'invoice:q3']))),
        );
    }

    public function testADecisionIsTriedWithEveryStepAnApisQuestionTakesAndItsReasonAlwaysGiven(): void
    {
        $this->adminToken();
        $outsider = $this->aPerson('outsider@example.com');

        self::assertSame(['decision' => true], self::document($this->tryDecision($this->reports, 'user', $this->ada)));
        // `denial_reasons` is off for the API; an operator is told why all the same.
        self::assertSame(
            ['decision' => false, 'context' => ['reason' => 'no_relation']],
            self::document($this->tryDecision($this->reports, 'user', $outsider)),
        );

        $users = $this->container()->get(UserRepository::class);
        $ada = $users->find($this->user()->id);
        self::assertNotNull($ada);
        $ada->deactivate($this->container()->get(Clock::class)->now());
        $users->save($ada);
        $asked = $this->engine->questions;
        self::assertSame(
            ['decision' => false, 'context' => ['reason' => 'subject_inactive']],
            self::document($this->tryDecision($this->reports, 'user', $this->ada)),
        );
        self::assertSame($asked, $this->engine->questions, 'A leaver is denied before the engine is asked.');
    }

    public function testAQuestionTheModelCannotTakeIsRefusedAtTheMemberAtFault(): void
    {
        $this->adminToken();
        $question = [
            'subject' => ['type' => 'user', 'id' => $this->ada],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => 'report', 'id' => 'q3'],
        ];

        foreach (
            [
                '/resource/type' => ['resource' => ['type' => 'invoice', 'id' => 'q3']] + $question,
                '/action/name' => ['action' => ['name' => 'approver']] + $question,
                '/subject/type' => ['subject' => ['type' => 'report', 'id' => 'q4']] + $question,
                '/context/clavia' => $question + ['context' => ['clavia' => ['subject' => ['roles' => ['admin']]]]],
            ] as $pointer => $body
        ) {
            $response = $this->api(
                RequestMethodInterface::METHOD_POST,
                sprintf(self::PATH, $this->reports->id->value, 'evaluation'),
                $body,
            );

            self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $response->getStatusCode(), $pointer);
            self::assertSame($pointer, self::document($response)['errors'][0]['pointer'] ?? null);
        }
        // The same question is the other API's to answer.
        self::assertSame(
            ['decision' => true],
            self::document($this->tryDecision($this->invoices, 'user', $this->ada, 'invoice')),
        );
    }

    public function testTheGraphNeedsReadRelationshipsAndTheVersionsReadResourceServers(): void
    {
        $this->adminToken(['read:resource_servers']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->read($this->reports, 'models')->getStatusCode());
        $asked = $this->engine->questions;
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->read($this->reports, 'relationships', ['object' => 'report:q3'])->getStatusCode(),
        );
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->tryDecision($this->reports, 'user', $this->ada)->getStatusCode(),
        );
        self::assertSame($asked, $this->engine->questions);

        $this->adminToken(['read:relationships']);
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $this->read($this->reports, 'models')->getStatusCode());
    }

    public function testAStoreSwitchedOffIsStillReadAndAnApiWithoutOneIsNotFound(): void
    {
        $this->adminToken();
        $settings = $this->reports->authorization;
        self::assertNotNull($settings);
        $this->container()->get(ResourceServerRepository::class)->save(
            $this->reports->withAuthorization($settings->disabled()),
        );

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->read($this->reports, 'models')->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->read($this->reports, 'relationships', ['object' => 'report:q3'])->getStatusCode(),
        );
        self::assertSame(['decision' => true], self::document($this->tryDecision($this->reports, 'user', $this->ada)));

        $none = $this->anApi('https://plain.test/api/', []);
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->read($none, 'models')->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $this->tryDecision($none, 'user', $this->ada)->getStatusCode(),
        );
    }

    public function testAnEngineThatDoesNotAnswerIsA503AndAServerWithoutOneAConflict(): void
    {
        $this->adminToken();
        $this->engine->goDown();

        foreach ($this->everyRead($this->reports) as $name => $response) {
            self::assertSame(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $response->getStatusCode(), $name);
        }

        $this->boot();
        $this->adminToken();
        foreach ($this->everyRead($this->reports) as $name => $response) {
            self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $response->getStatusCode(), $name);
        }
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @return list<array<string, mixed>>
     */
    private static function items(array $document): array
    {
        self::assertIsList($document['items'] ?? null);
        /** @var list<array<string, mixed>> */
        return $document['items'];
    }

    /** Another active person, holding nothing. */
    private function aPerson(string $email): string
    {
        $user = User::register(
            UserId::generate($this->container()->get(RandomSource::class)),
            $email,
            null,
            $this->container()->get(Clock::class)->now(),
        );
        $this->container()->get(UserRepository::class)->save($user);

        return $user->id->value;
    }

    /** @return array<string, ResponseInterface> */
    private function everyRead(ResourceServer $api): array
    {
        return [
            'models' => $this->read($api, 'models'),
            'relationships' => $this->read($api, 'relationships', ['object' => 'report:q3']),
            'evaluation' => $this->tryDecision($api, 'user', $this->ada),
        ];
    }

    /** @param array<string, string> $query */
    private function read(ResourceServer $api, string $what, array $query = []): ResponseInterface
    {
        return $this->api(
            RequestMethodInterface::METHOD_GET,
            sprintf(self::PATH, $api->id->value, $what),
            query: $query,
        );
    }

    private function tryDecision(
        ResourceServer $api,
        string $subjectType,
        string $subjectId,
        string $resourceType = 'report',
    ): ResponseInterface {
        return $this->api(RequestMethodInterface::METHOD_POST, sprintf(self::PATH, $api->id->value, 'evaluation'), [
            'subject' => ['type' => $subjectType, 'id' => $subjectId],
            'action' => ['name' => 'viewer'],
            'resource' => ['type' => $resourceType, 'id' => 'q3'],
        ]);
    }

    private function relate(ResourceServer $api, string ...$tuples): void
    {
        $settings = $api->authorization;
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
