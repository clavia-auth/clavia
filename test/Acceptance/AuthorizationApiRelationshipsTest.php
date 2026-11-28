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
use Clavia\Domain\ResourceServer\ResourceServer;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\AuthorizationApiFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * `POST|GET /access/v1/relationships` (#139, docs/design/fine-grained-authorization.md §5.3), against
 * the whole application with the decision engine's double: an API's own client writes and reads its
 * resources' relationships, in its own store only, and never Clavia's types. Every answer is checked
 * against `docs/openapi/authorization-api.yaml`.
 */
final class AuthorizationApiRelationshipsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use AuthorizationApiFixtures;

    private const string PATH = '/access/v1/relationships';

    /** People, applications, roles and teams, and documents they may view or edit, some under a condition. */
    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "client"},
          {"type": "role", "relations": {"member": {"this": {}}},
           "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
          {"type": "team", "relations": {"member": {"this": {}}},
           "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
          {"type": "document", "relations": {"viewer": {"this": {}}, "editor": {"this": {}}},
           "metadata": {"relations": {
             "viewer": {"directly_related_user_types": [
               {"type": "user"}, {"type": "client"}, {"type": "role", "relation": "member"},
               {"type": "user", "condition": "before_publication"}
             ]},
             "editor": {"directly_related_user_types": [{"type": "user"}, {"type": "team", "relation": "member"}]}
           }}}
        ],
        "conditions": {"before_publication": {"name": "before_publication",
          "expression": "now < publication",
          "parameters": {"now": {"type_name": "TYPE_NAME_TIMESTAMP"},
                         "publication": {"type_name": "TYPE_NAME_TIMESTAMP"}}}}}
        JSON;

    private const array FINANCE = ['type' => 'team', 'id' => 'finance', 'relation' => 'member'];
    private const array EDITORS = ['type' => 'role', 'id' => 'rol_AAAAAAAAAAAAAAAA', 'relation' => 'member'];
    private const array BEFORE_PUBLICATION = [
        'name' => 'before_publication',
        'context' => ['publication' => '2026-12-01T09:00:00Z'],
    ];
    private const string STRANGER = '0b7e1c55-8f3a-4c2d-9e6b-5a4f3e2d1c0b';

    private FakeDecisionEngine $engine;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_FGA_URL' => 'http://openfga.invalid:8080', 'CLAVIA_FGA_API_KEY' => str_repeat('k', 16)]);
        $this->engine = new FakeDecisionEngine();
        $this->container()->setService(DecisionEngine::class, $this->engine);
        $this->container()->get(RegisterAuthorizationApi::class)();
    }

    public function testAnApisRelationshipsAreWrittenAndReadBackAPageAtATime(): void
    {
        $token = $this->tokenSpeakingFor($this->api('https://documents.test/api/'), 'docs-backend');
        $ada = $this->user()->id->value;

        $written = $this->call($token, RequestMethodInterface::METHOD_POST, [
            'writes' => [
                self::relationship('document', 'q3', 'viewer', ['type' => 'user', 'id' => $ada]),
                self::relationship('document', 'q3', 'editor', self::FINANCE),
                self::relationship('document', 'q3', 'viewer', ['type' => 'client', 'id' => 'docs-backend']),
                self::relationship('document', 'q3', 'viewer', self::EDITORS),
                self::relationship('document', 'q4', 'viewer', ['type' => 'user', 'id' => $ada]) + [
                    'condition' => self::BEFORE_PUBLICATION,
                ],
            ],
        ]);
        self::assertSame(
            StatusCodeInterface::STATUS_NO_CONTENT,
            $written->getStatusCode(),
            (string) $written->getBody(),
        );

        $first = $this->read($token, ['object' => 'document:q3', 'page_size' => '3']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $first->getStatusCode(), (string) $first->getBody());
        $page = self::json($first);
        self::assertIsArray($page['items']);
        self::assertCount(3, $page['items']);
        self::assertIsString($page['next_page_token']);
        $second = self::json($this->read($token, [
            'object' => 'document:q3',
            'page_size' => '3',
            'page_token' => $page['next_page_token'],
        ]));
        self::assertIsArray($second['items']);
        self::assertCount(1, $second['items']);
        self::assertArrayNotHasKey('next_page_token', $second);

        $conditional = self::json($this->read($token, ['object' => 'document:q4']))['items'];
        self::assertIsArray($conditional);
        self::assertSame([
            'resource' => ['type' => 'document', 'id' => 'q4'],
            'relation' => 'viewer',
            'subject' => ['type' => 'user', 'id' => $ada],
            'condition' => self::BEFORE_PUBLICATION,
        ], $conditional[0] ?? null);

        // Deleted by what it is, whatever its condition.
        $deleted = $this->call($token, RequestMethodInterface::METHOD_POST, [
            'deletes' => [self::relationship('document', 'q4', 'viewer', ['type' => 'user', 'id' => $ada])],
        ]);
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $deleted->getStatusCode());
        self::assertSame([], self::json($this->read($token, ['object' => 'document:q4']))['items']);
    }

    public function testAnApiNeverReachesAnotherApisStoreOrTypes(): void
    {
        $documents = $this->api('https://documents.test/api/');
        $invoices = $this->api(
            'https://invoices.test/api/',
            str_replace('"document"', '"invoice"', self::MODEL),
        );
        $documentsToken = $this->tokenSpeakingFor($documents, 'docs-backend');
        $invoicesToken = $this->tokenSpeakingFor($invoices, 'invoices-backend');
        $ada = $this->user()->id->value;
        $this->call($invoicesToken, RequestMethodInterface::METHOD_POST, [
            'writes' => [self::relationship('invoice', '7', 'viewer', ['type' => 'user', 'id' => $ada])],
        ]);

        $written = $this->call($documentsToken, RequestMethodInterface::METHOD_POST, [
            'writes' => [self::relationship('invoice', '7', 'editor', ['type' => 'user', 'id' => $ada])],
        ]);
        self::assertRefusedAt($written, ['pointer' => '/writes/0/resource/type']);
        $read = $this->read($documentsToken, ['object' => 'invoice:7']);
        self::assertRefusedAt($read, ['parameter' => 'object']);
        self::assertSame(['invoice:7#viewer@user:' . $ada], $this->engine->relationshipsIn($this->storeOf($invoices)));
        self::assertSame([], $this->engine->relationshipsIn($this->storeOf($documents)));
    }

    public function testClaviasOwnTypesAreRefusedAndEverySubjectMustExist(): void
    {
        $api = $this->api('https://documents.test/api/');
        $token = $this->tokenSpeakingFor($api, 'docs-backend');
        $ada = $this->user()->id->value;
        $cases = [
            'a role membership' => [
                self::relationship('role', 'rol_AAAAAAAAAAAAAAAA', 'member', ['type' => 'user', 'id' => $ada]),
                '/writes/0/resource/type',
            ],
            'a person Clavia does not know' => [
                self::relationship('document', 'q3', 'viewer', ['type' => 'user', 'id' => self::STRANGER]),
                '/writes/0/subject/id',
            ],
            'an application Clavia does not know' => [
                self::relationship('document', 'q3', 'viewer', ['type' => 'client', 'id' => 'nobody']),
                '/writes/0/subject/id',
            ],
        ];

        foreach ($cases as $case => [$relationship, $pointer]) {
            self::assertRefusedAt(
                $this->call($token, RequestMethodInterface::METHOD_POST, ['writes' => [$relationship]]),
                ['pointer' => $pointer],
                $case,
            );
        }
        self::assertRefusedAt(
            $this->read($token, ['object' => 'role:rol_AAAAAAAAAAAAAAAA']),
            ['parameter' => 'object'],
        );
        self::assertSame([], $this->engine->relationshipsIn($this->storeOf($api)));
    }

    public function testAWriteIsAllOrNothingAndTheEnginesRefusalIsNamed(): void
    {
        $api = $this->api('https://documents.test/api/');
        $token = $this->tokenSpeakingFor($api, 'docs-backend');
        $ada = $this->user()->id->value;

        // The second one the model does not take: a team viewing a document.
        $response = $this->call($token, RequestMethodInterface::METHOD_POST, ['writes' => [
            self::relationship('document', 'q3', 'viewer', ['type' => 'user', 'id' => $ada]),
            self::relationship('document', 'q3', 'viewer', self::FINANCE),
        ]]);

        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $response->getStatusCode());
        self::assertStringContainsString('validation_error', (string) self::decoded($response)['detail']);
        self::assertSame([], $this->engine->relationshipsIn($this->storeOf($api)));

        $tooMany = array_map(
            static fn (int $i): array => self::relationship('document', "d$i", 'viewer', self::person($ada)),
            range(1, 60),
        );
        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $this->call(
            $token,
            RequestMethodInterface::METHOD_POST,
            ['writes' => $tooMany, 'deletes' => $tooMany],
        )->getStatusCode());
    }

    public function testOnlyAClientSpeakingForAnApiWithTheScopeIsAnswered(): void
    {
        $api = $this->api('https://documents.test/api/');
        $token = $this->tokenSpeakingFor($api, 'docs-backend');
        $silent = $this->clientWithAToken('stranger', 'write:relationships');
        $scopeless = $this->clientWithAToken('reader', 'evaluate:access');
        $body = ['writes' => []];

        $write = fn (?string $token): int => $this->call($token, RequestMethodInterface::METHOD_POST, $body)
            ->getStatusCode();
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $write(null));
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $write('not-a-token'));
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $write($scopeless));
        $speaksForNone = $this->call($silent, RequestMethodInterface::METHOD_POST, $body);
        self::assertSame(StatusCodeInterface::STATUS_FORBIDDEN, $speaksForNone->getStatusCode());
        self::assertSame('application/problem+json', $speaksForNone->getHeaderLine('Content-Type'));
        self::assertSame(StatusCodeInterface::STATUS_NO_CONTENT, $write($token));

        // The engine not answering is 503: never an answer, never a write assumed done.
        $this->engine->goDown();
        self::assertSame(
            StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
            $this->read($token, ['object' => 'document:q3'])->getStatusCode(),
        );
    }

    public function testTheRoutesExistOnlyWhileADecisionEngineIsNamed(): void
    {
        $this->boot();

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->request(
            RequestMethodInterface::METHOD_GET,
            self::PATH . '?object=document:q3',
            [],
            self::MANAGEMENT_HOST,
        )->getStatusCode());
    }

    /**
     * @param array<string, string> $subject
     *
     * @return array<string, mixed>
     */
    private static function relationship(string $type, string $id, string $relation, array $subject): array
    {
        return ['resource' => ['type' => $type, 'id' => $id], 'relation' => $relation, 'subject' => $subject];
    }

    #[\Override]
    protected function decisionEngine(): DecisionEngine
    {
        return $this->engine;
    }

    private function api(string $identifier, string $json = self::MODEL): ResourceServer
    {
        return $this->apiWithAuthorization($identifier, $json);
    }

    /** @param array<string, mixed> $body */
    private function call(?string $token, string $method, array $body): ResponseInterface
    {
        return $this->send($method, self::PATH, $token, json_encode($body, JSON_THROW_ON_ERROR));
    }

    /** @param array<string, string> $query */
    private function read(string $token, array $query): ResponseInterface
    {
        return $this->send(
            RequestMethodInterface::METHOD_GET,
            self::PATH . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986),
            $token,
            '',
        );
    }

    private function send(string $method, string $target, ?string $token, string $body): ResponseInterface
    {
        return $this->sendAccess($method, $target, $token, $body);
    }

    /** @param array{pointer?: string, parameter?: string} $where */
    private static function assertRefusedAt(ResponseInterface $response, array $where, string $case = ''): void
    {
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $response->getStatusCode(),
            $case . ' ' . (string) $response->getBody(),
        );
        $errors = self::decoded($response)['errors'] ?? [];
        self::assertIsArray($errors);
        self::assertSame($where, array_diff_key((array) ($errors[0] ?? []), ['detail' => true]), $case);
    }

    /** @return array{type: string, id: string} */
    private static function person(string $id): array
    {
        return ['type' => 'user', 'id' => $id];
    }
}
