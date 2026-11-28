<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Authorization;

use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\ModelPage;
use Clavia\Application\Port\ModelVersion;
use Clavia\Application\Port\TuplePage;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\Condition;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use InvalidArgumentException;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use stdClass;

/**
 * {@see DecisionEngine} on OpenFGA's HTTP API (https://openfga.dev/api/service), its stable,
 * native endpoints: stores, authorization models, write, check, batch check, list objects,
 * list users and read.
 *
 * OpenFGA is infrastructure, beside Clavia on its private network
 * (docs/design/fine-grained-authorization.md §2, §3): its URL is the operator's
 * (`CLAVIA_FGA_URL`), so it is not held to the outbound policy, and the client it is called with
 * is bounded by `CLAVIA_FGA_TIMEOUT` and follows no redirect. Every request carries the
 * preshared key (`Authorization: Bearer`), which only Clavia holds, so no API can reach the
 * engine around Clavia.
 *
 * Every failure is one {@see DecisionEngineFailed}: OpenFGA's own refusal of a request (a 4xx
 * with its error `code`) is a refusal with that code; anything else (unreachable, too slow, a
 * rejected key, a 5xx, an answer that is not what the API documents) is unavailable. Failures are
 * logged by operation and reason, never with what was sent or the key.
 */
final readonly class OpenFgaDecisionEngine implements DecisionEngine
{
    /** OpenFGA's default `--max-checks-per-batch-check`: a larger batch is sent in parts. */
    public const int BATCH_CHECK_MAX = 50;

    /** Tuples asked for per page when reading. OpenFGA's maximum page size is 100. */
    public const int READ_PAGE_SIZE = 100;

    /** How deep a page of models may nest: a model nests 64 deep at most, two more around it. */
    private const int MODEL_DEPTH = 128;

    private string $baseUrl;

    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
        string $baseUrl,
        #[\SensitiveParameter]
        private string $apiKey,
        private LoggerInterface $logger,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    #[\Override]
    public function createStore(string $name): StoreId
    {
        $answer = $this->send(RequestMethodInterface::METHOD_POST, '/stores', ['name' => $name], 'create store');

        return $this->read('create store', static fn (): StoreId => StoreId::fromString(self::string($answer, 'id')));
    }

    #[\Override]
    public function deleteStore(StoreId $store): void
    {
        $this->send(RequestMethodInterface::METHOD_DELETE, $this->store($store), null, 'delete store');
    }

    #[\Override]
    public function writeModel(StoreId $store, AuthorizationModel $model): AuthorizationModelId
    {
        $answer = $this->send(
            RequestMethodInterface::METHOD_POST,
            $this->store($store) . '/authorization-models',
            $model->json,
            'write model',
        );

        return $this->read(
            'write model',
            static fn (): AuthorizationModelId => AuthorizationModelId::fromString(
                self::string($answer, 'authorization_model_id'),
            ),
        );
    }

    #[\Override]
    public function readModels(StoreId $store, int $pageSize, string $continuation = ''): ModelPage
    {
        $query = ['page_size' => (string) min($pageSize, self::MAX_MODEL_PAGE)];
        if ($continuation !== '') {
            $query['continuation_token'] = $continuation;
        }
        [, $text] = $this->exchange(
            RequestMethodInterface::METHOD_GET,
            $this->store($store) . '/authorization-models?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986),
            null,
            'read models',
            self::MODEL_DEPTH,
        );

        return $this->read('read models', static function () use ($text): ModelPage {
            // Objects kept as objects: a model's `{}` is not `[]`.
            /** @var mixed $answer */
            $answer = json_decode($text, false, self::MODEL_DEPTH);
            /** @var mixed $models */
            $models = $answer instanceof stdClass ? ($answer->authorization_models ?? null) : null;
            if (! is_array($models)) {
                throw new InvalidValue('An answer lists its models.');
            }
            $versions = [];
            /** @var mixed $model */
            foreach ($models as $model) {
                /** @var mixed $id */
                $id = $model instanceof stdClass ? ($model->id ?? null) : null;
                if (! $model instanceof stdClass || ! is_string($id)) {
                    throw new InvalidValue('A model has an id.');
                }
                $model = clone $model;
                unset($model->id);
                try {
                    $json = json_encode(
                        $model,
                        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION,
                    );
                } catch (JsonException) {
                    throw new InvalidValue('A model is JSON.');
                }
                $versions[] = new ModelVersion(AuthorizationModelId::fromString($id), $json);
            }
            /** @var mixed $token */
            $token = $answer instanceof stdClass ? ($answer->continuation_token ?? '') : '';

            return new ModelPage($versions, is_string($token) ? $token : '');
        });
    }

    #[\Override]
    public function write(StoreId $store, AuthorizationModelId $model, array $writes, array $deletes = []): void
    {
        if (count($writes) + count($deletes) > self::MAX_WRITES) {
            throw new InvalidArgumentException(sprintf(
                'At most %d relationships are written or deleted at once.',
                self::MAX_WRITES,
            ));
        }
        if ($writes === [] && $deletes === []) {
            return;
        }

        $body = ['authorization_model_id' => $model->value];
        if ($writes !== []) {
            $body['writes'] = ['tuple_keys' => array_map(self::tupleKey(...), $writes)];
        }
        if ($deletes !== []) {
            $body['deletes'] = ['tuple_keys' => array_map(self::tupleKey(...), $deletes)];
        }

        $this->send(RequestMethodInterface::METHOD_POST, $this->store($store) . '/write', $body, 'write');
    }

    #[\Override]
    public function check(StoreId $store, AuthorizationModelId $model, AccessCheck $check): bool
    {
        $body = ['authorization_model_id' => $model->value, 'tuple_key' => self::checkKey($check)];
        if ($check->context !== []) {
            $body['context'] = $check->context;
        }

        $answer = $this->send(RequestMethodInterface::METHOD_POST, $this->store($store) . '/check', $body, 'check');
        $allowed = $answer['allowed'] ?? null;
        if (! is_bool($allowed)) {
            throw $this->unavailable('check', 'its answer has no decision');
        }

        return $allowed;
    }

    #[\Override]
    public function batchCheck(StoreId $store, AuthorizationModelId $model, array $checks): array
    {
        $decisions = [];
        foreach (array_chunk($checks, self::BATCH_CHECK_MAX) as $part) {
            array_push($decisions, ...$this->batchCheckPart($store, $model, $part));
        }

        return $decisions;
    }

    #[\Override]
    public function listObjects(
        StoreId $store,
        AuthorizationModelId $model,
        ObjectType $type,
        Relation $relation,
        SubjectRef $subject,
        array $context = [],
    ): array {
        $body = [
            'authorization_model_id' => $model->value,
            'type' => $type->value,
            'relation' => $relation->name,
            'user' => $subject->toString(),
        ];
        if ($context !== []) {
            $body['context'] = $context;
        }

        $answer = $this->send(
            RequestMethodInterface::METHOD_POST,
            $this->store($store) . '/list-objects',
            $body,
            'list objects',
        );

        return $this->read('list objects', static function () use ($answer): array {
            $objects = [];
            /** @var mixed $object */
            foreach (self::list($answer, 'objects') as $object) {
                $objects[] = ObjectRef::fromString(is_string($object) ? $object : '');
            }

            return $objects;
        });
    }

    #[\Override]
    public function listUsers(
        StoreId $store,
        AuthorizationModelId $model,
        ObjectRef $object,
        Relation $relation,
        ObjectType $subjectType,
        array $context = [],
    ): array {
        $body = [
            'authorization_model_id' => $model->value,
            'object' => ['type' => $object->type->value, 'id' => $object->id],
            'relation' => $relation->name,
            'user_filters' => [['type' => $subjectType->value]],
        ];
        if ($context !== []) {
            $body['context'] = $context;
        }

        $answer = $this->send(
            RequestMethodInterface::METHOD_POST,
            $this->store($store) . '/list-users',
            $body,
            'list users',
        );

        return $this->read('list users', static function () use ($answer): array {
            $users = [];
            /** @var mixed $user */
            foreach (self::list($answer, 'users') as $user) {
                // A wildcard (`{"wildcard": {"type": "user"}}`) or a userset names no one in
                // particular; only objects are subjects here (a wildcard is never written).
                $found = is_array($user) ? ($user['object'] ?? null) : null;
                if (! is_array($found)) {
                    continue;
                }
                $users[] = ObjectRef::of(
                    ObjectType::fromString(self::string($found, 'type')),
                    self::string($found, 'id'),
                );
            }

            return $users;
        });
    }

    #[\Override]
    public function readBySubject(StoreId $store, SubjectRef $subject, ObjectType $objectType): array
    {
        // A type alone, `document:`, asks for every object of the type (OpenFGA's Read).
        return $this->readTuples($store, ['user' => $subject->toString(), 'object' => $objectType->value . ':']);
    }

    #[\Override]
    public function readByObject(StoreId $store, ObjectRef $object): array
    {
        return $this->readTuples($store, ['object' => $object->toString()]);
    }

    #[\Override]
    public function readPage(StoreId $store, ObjectRef $object, int $pageSize, string $continuation = ''): TuplePage
    {
        [$tuples, $next] = $this->readOnePage($store, ['object' => $object->toString()], $pageSize, $continuation);

        return new TuplePage($tuples, $next);
    }

    /**
     * Every tuple matching the key, page after page.
     *
     * @param array<string, string> $key OpenFGA's `tuple_key`: an object, with or without a user.
     *
     * @return list<Tuple>
     */
    private function readTuples(StoreId $store, array $key): array
    {
        $tuples = [];
        $continuation = '';
        do {
            [$page, $continuation] = $this->readOnePage($store, $key, self::READ_PAGE_SIZE, $continuation);
            array_push($tuples, ...$page);
        } while ($continuation !== '');

        return $tuples;
    }

    /**
     * One page of OpenFGA's Read, and the token of the next ('' after the last).
     *
     * @param array<string, string> $key
     * @param positive-int $pageSize At most {@see self::READ_PAGE_SIZE}.
     *
     * @return array{list<Tuple>, string}
     */
    private function readOnePage(StoreId $store, array $key, int $pageSize, string $continuation): array
    {
        $body = ['tuple_key' => $key, 'page_size' => min($pageSize, self::READ_PAGE_SIZE)];
        if ($continuation !== '') {
            $body['continuation_token'] = $continuation;
        }

        $answer = $this->send(RequestMethodInterface::METHOD_POST, $this->store($store) . '/read', $body, 'read');

        return $this->read('read', static function () use ($answer): array {
            $page = [];
            /** @var mixed $tuple */
            foreach (self::list($answer, 'tuples') as $tuple) {
                $key = is_array($tuple) ? ($tuple['key'] ?? null) : null;
                if (! is_array($key)) {
                    throw new InvalidValue('A tuple has a key.');
                }
                $page[] = Tuple::of(
                    ObjectRef::fromString(self::string($key, 'object')),
                    Relation::fromString(self::string($key, 'relation')),
                    SubjectRef::fromString(self::string($key, 'user')),
                    self::condition($key['condition'] ?? null),
                );
            }
            /** @var mixed $token */
            $token = $answer['continuation_token'] ?? '';

            return [$page, is_string($token) ? $token : ''];
        });
    }

    /**
     * A tuple's condition as OpenFGA returns it: a name, and its context when one was stored.
     *
     * @throws InvalidValue When it is not that shape.
     */
    private static function condition(mixed $condition): ?Condition
    {
        if ($condition === null) {
            return null;
        }
        if (! is_array($condition)) {
            throw new InvalidValue('A condition is an object.');
        }
        /** @var mixed $context */
        $context = $condition['context'] ?? [];
        if (! is_array($context) || ($context !== [] && array_is_list($context))) {
            throw new InvalidValue('A condition\'s context is an object.');
        }
        /** @var array<string, mixed> $context */

        return Condition::of(self::string($condition, 'name'), $context);
    }

    /**
     * @param list<AccessCheck> $checks At most {@see self::BATCH_CHECK_MAX}.
     *
     * @return list<bool>
     */
    private function batchCheckPart(StoreId $store, AuthorizationModelId $model, array $checks): array
    {
        $items = [];
        foreach ($checks as $index => $check) {
            $item = ['tuple_key' => self::checkKey($check), 'correlation_id' => self::correlation($index)];
            if ($check->context !== []) {
                $item['context'] = $check->context;
            }
            $items[] = $item;
        }

        $answer = $this->send(
            RequestMethodInterface::METHOD_POST,
            $this->store($store) . '/batch-check',
            ['authorization_model_id' => $model->value, 'checks' => $items],
            'batch check',
        );
        $results = $answer['result'] ?? null;
        if (! is_array($results)) {
            throw $this->unavailable('batch check', 'its answer has no results');
        }

        $decisions = [];
        foreach (array_keys($checks) as $index) {
            /** @var mixed $result */
            $result = $results[self::correlation($index)] ?? null;
            /** @var mixed $error */
            $error = is_array($result) ? ($result['error'] ?? null) : null;
            // A check the engine refused (`{"error": {"input_error": "validation_error"}}`: a condition
            // it could not evaluate) is a refusal, as it is alone; any other error is no decision.
            /** @var mixed $refused */
            $refused = is_array($error) ? ($error['input_error'] ?? null) : null;
            if (is_string($refused) && preg_match('/^[a-z0-9_]{1,64}$/D', $refused) === 1) {
                $this->logger->notice('The decision engine refused {operation}: {code} ({status})', [
                    'operation' => 'batch check',
                    'code' => $refused,
                    'status' => StatusCodeInterface::STATUS_OK,
                ]);

                throw DecisionEngineFailed::refused($refused);
            }
            if (! is_array($result) || $error !== null) {
                throw $this->unavailable('batch check', 'a check has no decision');
            }
            /** @var mixed $allowed */
            $allowed = $result['allowed'] ?? null;
            if (! is_bool($allowed)) {
                throw $this->unavailable('batch check', 'a check has no decision');
            }
            $decisions[] = $allowed;
        }

        return $decisions;
    }

    /**
     * A correlation id for the check at `index` of a batch: OpenFGA's answer is keyed by it, and
     * its key is only ever looked up, never read back (PHP would turn `"10"` into `10`).
     */
    private static function correlation(int $index): string
    {
        return 'check-' . $index;
    }

    /**
     * One request to OpenFGA, and its JSON answer.
     *
     * @param array<string, mixed>|string|null $body A JSON body, as data or as text; none for null.
     *
     * @return array<array-key, mixed> The answer's members; none for an empty answer.
     *
     * @throws DecisionEngineFailed
     */
    private function send(string $method, string $path, array|string|null $body, string $operation): array
    {
        return $this->exchange($method, $path, $body, $operation)[0];
    }

    /**
     * One request and its answer: the members, and the text they were read from.
     *
     * @param array<array-key, mixed>|string|null $body
     * @param int<1, 2147483647> $depth How deep the answer may nest.
     *
     * @return array{array<array-key, mixed>, string}
     *
     * @throws DecisionEngineFailed
     */
    private function exchange(
        string $method,
        string $path,
        array|string|null $body,
        string $operation,
        int $depth = 64,
    ): array {
        $request = $this->requests->createRequest($method, $this->baseUrl . $path)
            ->withHeader('Authorization', 'Bearer ' . $this->apiKey)
            ->withHeader('Accept', 'application/json');
        if ($body !== null) {
            try {
                $json = is_string($body)
                    ? $body
                    : json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
            } catch (JsonException) {
                throw new InvalidArgumentException('A context is a JSON object.');
            }
            $request = $request
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streams->createStream($json));
        }

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $failure) {
            throw $this->unavailable($operation, sprintf('it could not be reached (%s)', $failure::class));
        }

        $status = $response->getStatusCode();
        $text = (string) $response->getBody();
        try {
            $answer = $text === '' ? [] : json_decode($text, true, $depth, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $answer = null;
        }

        if ($status >= 200 && $status < 300) {
            if (! is_array($answer)) {
                throw $this->unavailable($operation, sprintf('it answered %d with no JSON object', $status));
            }

            return [$answer, $text];
        }
        if (self::isRefusal($status)) {
            /** @var mixed $code */
            $code = is_array($answer) ? ($answer['code'] ?? null) : null;
            $code = is_string($code) && preg_match('/^[a-z0-9_]{1,64}$/D', $code) === 1 ? $code : 'unknown';
            $this->logger->notice('The decision engine refused {operation}: {code} ({status})', [
                'operation' => $operation,
                'code' => $code,
                'status' => $status,
            ]);

            throw DecisionEngineFailed::refused($code);
        }

        throw $this->unavailable($operation, sprintf('it answered %d', $status));
    }

    /**
     * A 4xx about the request itself: OpenFGA's validation and its unknown stores and models. Not
     * a rejected key (401, 403: this server's configuration), a timeout (408) or a rate limit
     * (429), which say nothing of the request and are the engine being unavailable to it.
     */
    private static function isRefusal(int $status): bool
    {
        return $status >= 400 && $status < 500 && ! in_array($status, [
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            StatusCodeInterface::STATUS_FORBIDDEN,
            StatusCodeInterface::STATUS_REQUEST_TIMEOUT,
            StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
        ], true);
    }

    /**
     * What an answer holds, read by `reader`, or unavailable when it is not what the API documents.
     *
     * @template T
     *
     * @param callable(): T $reader
     *
     * @return T
     */
    private function read(string $operation, callable $reader): mixed
    {
        try {
            return $reader();
        } catch (InvalidValue) {
            throw $this->unavailable($operation, 'its answer is not one the API documents');
        }
    }

    private function unavailable(string $operation, string $reason): DecisionEngineFailed
    {
        $this->logger->warning('The decision engine failed to {operation}: {reason}', [
            'operation' => $operation,
            'reason' => $reason,
        ]);

        return DecisionEngineFailed::unavailable();
    }

    private function store(StoreId $store): string
    {
        return '/stores/' . rawurlencode($store->value);
    }

    /** @return array<string, mixed> OpenFGA's tuple key, and the tuple's condition when it has one. */
    private static function tupleKey(Tuple $tuple): array
    {
        $key = [
            'user' => $tuple->subject->toString(),
            'relation' => $tuple->relation->name,
            'object' => $tuple->object->toString(),
        ];
        if ($tuple->condition !== null) {
            $key['condition'] = ['name' => $tuple->condition->name];
            if ($tuple->condition->context !== []) {
                $key['condition']['context'] = $tuple->condition->context;
            }
        }

        return $key;
    }

    /** @return array{user: string, relation: string, object: string} */
    private static function checkKey(AccessCheck $check): array
    {
        return [
            'user' => $check->subject->toString(),
            'relation' => $check->relation->name,
            'object' => $check->object->toString(),
        ];
    }

    /**
     * @param array<array-key, mixed> $answer
     *
     * @throws InvalidValue When the member is not a string.
     */
    private static function string(array $answer, string $member): string
    {
        $value = $answer[$member] ?? null;
        if (! is_string($value)) {
            throw new InvalidValue(sprintf('The answer has no %s.', $member));
        }

        return $value;
    }

    /**
     * @param array<array-key, mixed> $answer
     *
     * @return list<mixed>
     *
     * @throws InvalidValue When the member is not a list.
     */
    private static function list(array $answer, string $member): array
    {
        $value = $answer[$member] ?? [];
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidValue(sprintf('The answer has no list of %s.', $member));
        }

        return $value;
    }
}
