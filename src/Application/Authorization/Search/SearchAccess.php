<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Search;

use Clavia\Application\Authorization\Evaluation\EvaluationRefused;
use Clavia\Application\Authorization\Evaluation\QuestionRules;
use Clavia\Application\Authorization\Evaluation\SubjectFacts;
use Clavia\Application\Authorization\SpeaksForNoApi;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\InvalidValue;
use stdClass;

/**
 * AuthZEN's Subject, Resource and Action Search (AuthZEN 1.0 §8; docs/design/fine-grained-authorization.md
 * §5.5), answered from the store of the API the caller's client speaks for, under the evaluation's rules
 * ({@see QuestionRules}).
 *
 * - **Subjects** (`list-users`): the people or applications holding the relation on the resource,
 *   transitively (§8.1). Deactivated or unknown accounts and deleted clients are left out. The engine
 *   cannot be told each candidate's facts, so `clavia` is an empty map there: a relationship whose
 *   condition reads Clavia's subject facts does not count, provided the condition guards with
 *   `has(clavia.subject)`; one that does not makes the engine refuse the whole listing.
 * - **Resources** (`list-objects`): the objects of the type the subject holds the relation on, its facts
 *   in the context as for an evaluation.
 * - **Actions**: every relation of the resource's type, asked in one batch.
 *
 * A subject that is not one to ask about (no account, deactivated, a deleted application) has no
 * resources and no actions; the engine is not asked. A listing the engine refuses to evaluate has no
 * results and says why, failing closed. Results are capped at what the engine returns, at most
 * {@see self::MAX_RESULTS}, sorted by id so pages are stable, and paged statelessly: the token names
 * where the next page starts and the search it belongs to (§8.2).
 */
final readonly class SearchAccess
{
    /** The most results a search considers: OpenFGA's own list maximum (1,000) by default. */
    public const int MAX_RESULTS = 1000;

    private const string REFUSED = 'The decision engine could not evaluate a condition for this search: a condition '
        . 'reads a parameter the request does not give, or reads `clavia` without `has(clavia.subject)`.';

    /**
     * @param positive-int $maxResults
     */
    public function __construct(
        private SpokenForApi $apis,
        private DecisionEngine $engine,
        private SubjectFacts $facts,
        private UserRepository $users,
        private ClientRepository $clients,
        private int $maxResults = self::MAX_RESULTS,
    ) {
    }

    /**
     * @throws SpeaksForNoApi
     * @throws EvaluationRefused A question that cannot be asked, or a page token not this search's: 400.
     * @throws DecisionEngineFailed When the engine gives no answer.
     */
    public function subjects(ClientId $caller, SearchRequest $search): SearchResults
    {
        [, $settings] = $this->apis->of($caller);
        $model = $settings->model;
        QuestionRules::context($search->context);
        $subjectType = QuestionRules::subjectType($model, $search->subjectType);
        $resourceType = QuestionRules::resourceType($model, $search->resourceType);
        $relation = QuestionRules::relation($model, $resourceType, $search->action);
        $resource = QuestionRules::object($resourceType, $search->resourceId);
        $offset = self::offset($search, SearchKind::Subject);

        try {
            $found = $this->engine->listUsers(
                $settings->store,
                $settings->modelId,
                $resource,
                $relation,
                $subjectType,
                // No subject yet: Clavia's facts are an empty map, so a guarded condition does not hold.
                $search->context + ['clavia' => new stdClass()],
            );
        } catch (DecisionEngineFailed $failed) {
            return self::refused($failed);
        }

        $ids = $this->sorted(array_map(static fn (ObjectRef $subject): string => $subject->id, $found));

        return self::page(
            $ids,
            $offset,
            $search,
            SearchKind::Subject,
            fn (string $id): bool => $this->exists($subjectType->value, $id),
        );
    }

    /**
     * @throws SpeaksForNoApi
     * @throws EvaluationRefused
     * @throws DecisionEngineFailed
     */
    public function resources(ClientId $caller, SearchRequest $search): SearchResults
    {
        [$api, $settings] = $this->apis->of($caller);
        $model = $settings->model;
        QuestionRules::context($search->context);
        $subjectType = QuestionRules::subjectType($model, $search->subjectType);
        $resourceType = QuestionRules::resourceType($model, $search->resourceType);
        $relation = QuestionRules::relation($model, $resourceType, $search->action);
        $subject = QuestionRules::object($subjectType, $search->subjectId);
        $offset = self::offset($search, SearchKind::Resource);
        $context = $this->contextFor($api, $search);
        if ($context === null) {
            return SearchResults::none();
        }

        try {
            $found = $this->engine->listObjects(
                $settings->store,
                $settings->modelId,
                $resourceType,
                $relation,
                SubjectRef::object($subject),
                $context,
            );
        } catch (DecisionEngineFailed $failed) {
            return self::refused($failed);
        }

        return self::page(
            $this->sorted(array_map(static fn (ObjectRef $object): string => $object->id, $found)),
            $offset,
            $search,
            SearchKind::Resource,
        );
    }

    /**
     * @throws SpeaksForNoApi
     * @throws EvaluationRefused
     * @throws DecisionEngineFailed
     */
    public function actions(ClientId $caller, SearchRequest $search): SearchResults
    {
        [$api, $settings] = $this->apis->of($caller);
        $model = $settings->model;
        QuestionRules::context($search->context);
        $subjectType = QuestionRules::subjectType($model, $search->subjectType);
        $resourceType = QuestionRules::resourceType($model, $search->resourceType);
        $subject = SubjectRef::object(QuestionRules::object($subjectType, $search->subjectId));
        $resource = QuestionRules::object($resourceType, $search->resourceId);
        $offset = self::offset($search, SearchKind::Action);
        $context = $this->contextFor($api, $search);
        $relations = $model->relationsOf($resourceType);
        if ($context === null || $relations === []) {
            return SearchResults::none();
        }

        $checks = array_map(
            static fn (Relation $relation): AccessCheck => AccessCheck::of($resource, $relation, $subject, $context),
            $relations,
        );
        $held = [];
        foreach ($this->answers($settings, $checks) as $index => $allowed) {
            if ($allowed) {
                $held[] = $relations[$index]->name;
            }
        }

        // In the model's order: the order its author gave the relations.
        return self::page($held, $offset, $search, SearchKind::Action);
    }

    /**
     * Each relation's answer; one the engine refuses to evaluate is not held, the others still asked.
     *
     * @param list<AccessCheck> $checks
     *
     * @return list<bool>
     *
     * @throws DecisionEngineFailed When the engine gives no answer at all.
     */
    private function answers(AuthorizationSettings $settings, array $checks): array
    {
        try {
            return $this->engine->batchCheck($settings->store, $settings->modelId, $checks);
        } catch (DecisionEngineFailed $failed) {
            if ($failed->refusal === null) {
                throw $failed;
            }
        }

        $answers = [];
        foreach ($checks as $check) {
            try {
                $answers[] = $this->engine->check($settings->store, $settings->modelId, $check);
            } catch (DecisionEngineFailed $failed) {
                if ($failed->refusal === null) {
                    throw $failed;
                }
                $answers[] = false;
            }
        }

        return $answers;
    }

    /** @return array<string, mixed>|null The search's context with the subject's facts; null for a subject not to ask about. */
    private function contextFor(ResourceServer $api, SearchRequest $search): ?array
    {
        $facts = $this->facts->of($api, $search->subjectType, $search->subjectId);

        return $facts === null ? null : $search->context + ['clavia' => ['subject' => $facts]];
    }

    /** Whether a subject the engine named is still one to name: an active account, an existing application. */
    private function exists(string $type, string $id): bool
    {
        try {
            if ($type === 'user') {
                return $this->users->find(UserId::fromString($id))?->isActive() === true;
            }

            return $this->clients->find(ClientId::fromString($id)) !== null;
        } catch (InvalidValue) {
            return false;
        }
    }

    /**
     * Distinct, by id, at most {@see self::$maxResults}.
     *
     * @param list<string> $ids
     *
     * @return list<string>
     */
    private function sorted(array $ids): array
    {
        $ids = array_values(array_unique($ids));
        sort($ids, SORT_STRING);

        return array_slice($ids, 0, $this->maxResults);
    }

    /**
     * The page from `$offset`: up to the limit of ids `$keep` keeps, and where the next one starts.
     *
     * @param list<string> $ids
     * @param (callable(string): bool)|null $keep
     */
    private static function page(
        array $ids,
        int $offset,
        SearchRequest $search,
        SearchKind $kind,
        ?callable $keep = null,
    ): SearchResults {
        $page = [];
        $at = $offset;
        while ($at < count($ids) && count($page) < $search->limit) {
            $id = $ids[$at++];
            if ($keep === null || $keep($id)) {
                $page[] = $id;
            }
        }

        return new SearchResults($page, $at < count($ids) ? self::token($at, $search, $kind) : '');
    }

    private static function refused(DecisionEngineFailed $failed): SearchResults
    {
        if ($failed->refusal === null) {
            throw $failed;
        }

        return SearchResults::none(self::REFUSED);
    }

    private static function token(int $offset, SearchRequest $search, SearchKind $kind): string
    {
        return rtrim(strtr(base64_encode(json_encode(
            ['o' => $offset, 'f' => $search->fingerprint($kind)],
            JSON_THROW_ON_ERROR,
        )), '+/', '-_'), '=');
    }

    /**
     * Where the page starts: 0, or what the token says, if the token is this search's.
     *
     * @throws EvaluationRefused
     */
    private static function offset(SearchRequest $search, SearchKind $kind): int
    {
        if ($search->pageToken === '') {
            return 0;
        }
        $json = base64_decode(strtr($search->pageToken, '-_', '+/'), true);
        /** @var mixed $decoded */
        $decoded = $json === false ? null : json_decode($json, true, 4);
        /** @var mixed $offset */
        $offset = is_array($decoded) ? ($decoded['o'] ?? null) : null;
        /** @var mixed $fingerprint */
        $fingerprint = is_array($decoded) ? ($decoded['f'] ?? null) : null;
        if (
            ! is_int($offset)
            || $offset < 0
            || ! is_string($fingerprint)
            || ! hash_equals($search->fingerprint($kind), $fingerprint)
        ) {
            throw EvaluationRefused::pageToken();
        }

        return $offset;
    }
}
