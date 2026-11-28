<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Authorization;

use Clavia\Adapter\Secondary\Authorization\OpenFgaDecisionEngine;
use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\RecordingLogger;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\Response\TextResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * What goes over the wire to OpenFGA, and how its answers are read; the behaviour itself is held
 * to the contract against a real OpenFGA (`ClaviaTest\Integration\Authorization`).
 */
final class OpenFgaDecisionEngineTest extends TestCase
{
    private const string KEY = 'a-preshared-key-only-clavia-holds';

    private const string STORE = '01JAAAAAAAAAAAAAAAAAAAAAAA';

    private const string MODEL = '01JBBBBBBBBBBBBBBBBBBBBBBB';

    private FakeHttpClient $http;

    private RecordingLogger $logger;

    #[\Override]
    protected function setUp(): void
    {
        $this->http = new FakeHttpClient();
        $this->logger = new RecordingLogger();
    }

    public function testEveryRequestCarriesThePresharedKeyToTheEnginesUrl(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['id' => self::STORE]));

        $store = $this->engine('http://openfga:8080/')->createStore('reports-api');

        self::assertSame(self::STORE, $store->value);
        $request = $this->http->requests[0];
        self::assertSame(RequestMethodInterface::METHOD_POST, $request->getMethod());
        self::assertSame('http://openfga:8080/stores', (string) $request->getUri());
        self::assertSame('Bearer ' . self::KEY, $request->getHeaderLine('Authorization'));
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
        self::assertSame(['name' => 'reports-api'], self::body($request));
    }

    public function testAModelIsSentAsTheJsonItCameAs(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(
            ['authorization_model_id' => self::MODEL],
            StatusCodeInterface::STATUS_CREATED,
        ));

        $model = $this->engine()->writeModel(
            self::store(),
            AuthorizationModel::fromJson(DecisionEngineContract::MODEL),
        );

        self::assertSame(self::MODEL, $model->value);
        $request = $this->http->requests[0];
        self::assertSame(
            'http://openfga:8080/stores/' . self::STORE . '/authorization-models',
            (string) $request->getUri(),
        );
        // `"this": {}` stays an object: decoded and encoded again, it would be a list.
        self::assertSame(DecisionEngineContract::MODEL, (string) $request->getBody());
    }

    public function testACheckNamesTheModelTheTupleAndOnlyAContextGiven(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['allowed' => true]));

        self::assertTrue($this->engine()->check(self::store(), self::model(), self::question()));
        self::assertTrue($this->engine()->check(self::store(), self::model(), self::question(['plan' => 'pro'])));

        self::assertSame([
            'authorization_model_id' => self::MODEL,
            'tuple_key' => ['user' => 'user:ada', 'relation' => 'viewer', 'object' => 'document:1'],
        ], self::body($this->http->requests[0]));
        self::assertSame(['plan' => 'pro'], self::body($this->http->requests[1])['context']);
    }

    public function testABatchLargerThanTheEnginesLimitIsSentInPartsAndAnsweredInOrder(): void
    {
        $this->http->answerWith(static function (RequestInterface $request): ResponseInterface {
            $result = [];
            /** @var list<array{correlation_id: string, tuple_key: array{object: string}}> $checks */
            $checks = self::body($request)['checks'];
            foreach ($checks as $check) {
                $result[$check['correlation_id']] = ['allowed' => $check['tuple_key']['object'] === 'document:1'];
            }

            return new JsonResponse(['result' => $result]);
        });
        $checks = [];
        foreach (range(1, 60) as $i) {
            $checks[] = AccessCheck::of(
                ObjectRef::fromString('document:' . ($i % 2)),
                Relation::fromString('viewer'),
                SubjectRef::fromString('user:ada'),
            );
        }

        $decisions = $this->engine()->batchCheck(self::store(), self::model(), $checks);

        self::assertCount(2, $this->http->requests);
        self::assertSame(OpenFgaDecisionEngine::BATCH_CHECK_MAX, self::sizeOf($this->http->requests[0], 'checks'));
        self::assertSame(10, self::sizeOf($this->http->requests[1], 'checks'));
        self::assertSame(array_map(static fn (int $i): bool => $i % 2 === 1, range(1, 60)), $decisions);
    }

    public function testABatchWithACheckTheEngineCouldNotAnswerGivesNoDecisions(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['result' => [
            'check-0' => ['allowed' => true],
            'check-1' => ['allowed' => false, 'error' => ['message' => 'deadline exceeded']],
        ]]));

        $this->expectException(DecisionEngineFailed::class);

        $this->engine()->batchCheck(self::store(), self::model(), [self::question(), self::question()]);
    }

    public function testListingUsersKeepsOnlyObjects(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['users' => [
            ['object' => ['type' => 'user', 'id' => 'ada']],
            ['wildcard' => ['type' => 'user']],
            ['userset' => ['type' => 'team', 'id' => 'sales', 'relation' => 'member']],
        ]]));

        $users = $this->engine()->listUsers(
            self::store(),
            self::model(),
            ObjectRef::fromString('document:1'),
            Relation::fromString('viewer'),
            ObjectType::fromString('user'),
        );

        self::assertSame(['user:ada'], array_map(static fn (ObjectRef $user): string => $user->toString(), $users));
        self::assertSame([['type' => 'user']], self::body($this->http->requests[0])['user_filters']);
    }

    public function testReadingBySubjectFollowsTheContinuation(): void
    {
        $this->http->answerWith(static function (RequestInterface $request): ResponseInterface {
            $first = ! isset(self::body($request)['continuation_token']);

            return new JsonResponse([
                'tuples' => [['key' => [
                    'user' => 'user:ada',
                    'relation' => 'viewer',
                    'object' => $first ? 'document:1' : 'document:2',
                ]]],
                'continuation_token' => $first ? 'next-page' : '',
            ]);
        });

        $tuples = $this->engine()->readBySubject(
            self::store(),
            SubjectRef::fromString('user:ada'),
            ObjectType::fromString('document'),
        );

        self::assertCount(2, $tuples);
        self::assertSame('document:2#viewer@user:ada', $tuples[1]->toString());
        self::assertSame(
            ['tuple_key' => ['user' => 'user:ada', 'object' => 'document:'], 'page_size' => 100],
            self::body($this->http->requests[0]),
        );
        self::assertSame('next-page', self::body($this->http->requests[1])['continuation_token']);
    }

    public function testModelVersionsAreReadAPageAtATimeWithTheirObjectsKept(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new TextResponse(
            '{"authorization_models": [{"id": "' . self::MODEL . '", "schema_version": "1.1", '
            . '"type_definitions": [{"type": "user", "relations": {}, "metadata": null}, '
            . '{"type": "role", "relations": {"member": {"this": {}}}}], "conditions": {}}], '
            . '"continuation_token": "next-page"}',
            headers: ['Content-Type' => 'application/json'],
        ));

        $page = $this->engine()->readModels(self::store(), 10, 'this-page');

        $request = $this->http->requests[0];
        self::assertSame(RequestMethodInterface::METHOD_GET, $request->getMethod());
        self::assertSame(
            'http://openfga:8080/stores/' . self::STORE
            . '/authorization-models?page_size=10&continuation_token=this-page',
            (string) $request->getUri(),
        );
        self::assertSame('next-page', $page->next);
        self::assertCount(1, $page->models);
        self::assertSame(self::MODEL, $page->models[0]->id->value);
        // The id is the version's, not the model's; `{}` stays an object.
        self::assertSame(
            '{"schema_version":"1.1","type_definitions":[{"type":"user","relations":{},"metadata":null},'
            . '{"type":"role","relations":{"member":{"this":{}}}}],"conditions":{}}',
            $page->models[0]->json,
        );
    }

    public function testAPageOfModelsIsNeverLargerThanTheEnginesLargest(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['authorization_models' => []]));

        $page = $this->engine()->readModels(self::store(), 500);

        self::assertSame([], $page->models);
        self::assertSame('', $page->next);
        self::assertStringEndsWith('?page_size=50', (string) $this->http->requests[0]->getUri());
    }

    public function testDeletingAStoreExpectsNoAnswerBody(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new EmptyResponse());

        $this->engine()->deleteStore(self::store());

        self::assertSame(RequestMethodInterface::METHOD_DELETE, $this->http->requests[0]->getMethod());
        self::assertSame('http://openfga:8080/stores/' . self::STORE, (string) $this->http->requests[0]->getUri());
    }

    public function testARefusalCarriesTheEnginesCodeAndNothingElse(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(
            ['code' => 'validation_error', 'message' => 'type "invoice" not found for user:ada'],
            StatusCodeInterface::STATUS_BAD_REQUEST,
        ));

        try {
            $this->engine()->check(self::store(), self::model(), self::question());
            self::fail('The refusal was taken for a decision.');
        } catch (DecisionEngineFailed $refused) {
            self::assertSame('validation_error', $refused->refusal);
            self::assertStringNotContainsString('ada', $refused->getMessage());
        }
        self::assertFalse($this->logger->hasRecordContaining('ada'));
    }

    public function testACodeThatIsNotOneIsUnknown(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(
            ['code' => '<script>'],
            StatusCodeInterface::STATUS_BAD_REQUEST,
        ));

        try {
            $this->engine()->check(self::store(), self::model(), self::question());
            self::fail('The refusal was taken for a decision.');
        } catch (DecisionEngineFailed $refused) {
            self::assertSame('unknown', $refused->refusal);
        }
    }

    /** @return iterable<string, array{callable(RequestInterface): ResponseInterface}> */
    public static function answersThatAreNoAnswer(): iterable
    {
        yield 'a rejected key' => [static fn (): ResponseInterface => new JsonResponse(
            ['code' => 'unauthenticated'],
            StatusCodeInterface::STATUS_UNAUTHORIZED,
        )];
        yield 'a rate limit' => [static fn (): ResponseInterface => new JsonResponse(
            ['code' => 'rate_limit_exceeded'],
            StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
        )];
        yield 'a failure of its own' => [static fn (): ResponseInterface => new JsonResponse(
            ['code' => 'internal_error'],
            StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR,
        )];
        yield 'a deadline' => [static fn (): ResponseInterface => new JsonResponse(
            ['code' => 'deadline_exceeded'],
            StatusCodeInterface::STATUS_GATEWAY_TIMEOUT,
        )];
        yield 'not JSON' => [static fn (): ResponseInterface => new TextResponse('<html>')];
        yield 'no decision' => [static fn (): ResponseInterface => new JsonResponse(['allowed' => 'yes'])];
        yield 'not reached' => [static function (RequestInterface $request): ResponseInterface {
            throw new ConnectException('Connection refused', $request);
        }];
    }

    /** @param callable(RequestInterface): ResponseInterface $answer */
    #[DataProvider('answersThatAreNoAnswer')]
    public function testAnythingButAnAnswerOrARefusalIsUnavailableAndNeverLogsTheKey(callable $answer): void
    {
        $this->http->answerWith($answer);

        try {
            $this->engine()->check(self::store(), self::model(), self::question());
            self::fail('A failure was taken for a decision.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNull($failed->refusal);
        }
        self::assertNotSame([], $this->logger->records);
        self::assertFalse($this->logger->hasRecordContaining(self::KEY));
    }

    public function testAnAnswerNamingNoValidObjectIsUnavailable(): void
    {
        $this->http->answerWith(static fn (): ResponseInterface => new JsonResponse(['objects' => ['document']]));

        try {
            $this->engine()->listObjects(
                self::store(),
                self::model(),
                ObjectType::fromString('document'),
                Relation::fromString('viewer'),
                SubjectRef::fromString('user:ada'),
            );
            self::fail('A malformed answer was read.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNull($failed->refusal);
        }
    }

    private function engine(string $url = 'http://openfga:8080'): OpenFgaDecisionEngine
    {
        return new OpenFgaDecisionEngine(
            $this->http,
            new RequestFactory(),
            new StreamFactory(),
            $url,
            self::KEY,
            $this->logger,
        );
    }

    private static function store(): StoreId
    {
        return StoreId::fromString(self::STORE);
    }

    private static function model(): AuthorizationModelId
    {
        return AuthorizationModelId::fromString(self::MODEL);
    }

    /** @param array<string, mixed> $context */
    private static function question(array $context = []): AccessCheck
    {
        return AccessCheck::of(
            ObjectRef::fromString('document:1'),
            Relation::fromString('viewer'),
            SubjectRef::fromString('user:ada'),
            $context,
        );
    }

    private static function sizeOf(RequestInterface $request, string $member): int
    {
        /** @var mixed $value */
        $value = self::body($request)[$member] ?? null;

        return is_array($value) ? count($value) : -1;
    }

    /** @return array<string, mixed> */
    private static function body(RequestInterface $request): array
    {
        $body = $request->getBody();
        $body->rewind();
        /** @var array<string, mixed> */
        return json_decode($body->getContents(), true, 64, JSON_THROW_ON_ERROR);
    }
}
