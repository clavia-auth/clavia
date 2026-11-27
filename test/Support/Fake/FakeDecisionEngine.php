<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use InvalidArgumentException;
use LogicException;

/**
 * An in-memory {@see DecisionEngine}: a small evaluator of OpenFGA's models, for the use cases'
 * tests. `DecisionEngineContract` holds it to what OpenFGA does.
 *
 * It works out the **union subset** of schema 1.1: a relation is direct (`this`, with the types
 * and usersets it takes), another relation of the same object (`computedUserset`), a relation of
 * a related object (`tupleToUserset`, "viewer from parent"), or a union of these. A model using
 * anything else (an intersection, an exclusion, a condition, a wildcard) is a test asking more of
 * the double than it does: a {@see LogicException}, never a wrong answer.
 *
 * Refusals use OpenFGA's codes: `invalid_authorization_model` for a model that does not hold
 * together, `validation_error` for a tuple or a question the model does not take,
 * `store_id_not_found`, `authorization_model_not_found`, and `write_failed_due_to_invalid_input`
 * for a tuple written twice or deleted unwritten. A deleted store is gone here; OpenFGA's own
 * deletion is soft (see {@see DecisionEngine::deleteStore()}).
 */
/**
 * @psalm-type Definition = array{rewrite: array<array-key, mixed>, takes: list<string>}
 * @psalm-type Relations = array<string, array<string, Definition>>
 */
final class FakeDecisionEngine implements DecisionEngine
{
    /**
     * Per store, each model's relations by type, then by name: the rewrite, and the subject types
     * a direct relation takes (`user`, `team#member`).
     *
     * @var array<string, array<string, Relations>>
     */
    private array $models = [];

    /** @var array<string, array<string, Tuple>> Per store, the tuples by their notation. */
    private array $tuples = [];

    private int $ids = 0;

    private bool $unavailable = false;

    /** How many questions have been asked: a test that must not reach the engine says none. */
    public int $questions = 0;

    /** Every later call fails as an engine that cannot be reached. */
    public function goDown(): void
    {
        $this->unavailable = true;
    }

    /** The engine answers again. */
    public function comeBack(): void
    {
        $this->unavailable = false;
    }

    /** Whether the store exists: a test that deleted one, or left none behind, says so. */
    public function hasStore(StoreId $store): bool
    {
        return isset($this->models[$store->value]);
    }

    /** How many stores exist. */
    public function storeCount(): int
    {
        return count($this->models);
    }

    #[\Override]
    public function createStore(string $name): StoreId
    {
        $this->reachable();
        if (preg_match('/^[a-zA-Z0-9\s.\-\/^_&@]{3,64}$/D', $name) !== 1) {
            throw DecisionEngineFailed::refused('validation_error');
        }
        $store = StoreId::fromString($this->nextUlid());
        $this->models[$store->value] = [];
        $this->tuples[$store->value] = [];

        return $store;
    }

    #[\Override]
    public function deleteStore(StoreId $store): void
    {
        $this->reachable();
        $this->storeOf($store);
        unset($this->models[$store->value], $this->tuples[$store->value]);
    }

    #[\Override]
    public function writeModel(StoreId $store, AuthorizationModel $model): AuthorizationModelId
    {
        $this->reachable();
        $this->storeOf($store);
        $relations = self::relationsOf($model);
        $id = AuthorizationModelId::fromString($this->nextUlid());
        $this->models[$store->value][$id->value] = $relations;

        return $id;
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
        $this->reachable();
        $relations = $this->modelOf($store, $model);
        if ($writes === [] && $deletes === []) {
            return;
        }

        $tuples = $this->tuples[$store->value];
        foreach ($deletes as $tuple) {
            if (! isset($tuples[$tuple->toString()])) {
                throw DecisionEngineFailed::refused('write_failed_due_to_invalid_input');
            }
            unset($tuples[$tuple->toString()]);
        }
        foreach ($writes as $tuple) {
            self::allowed($relations, $tuple);
            if (isset($tuples[$tuple->toString()])) {
                throw DecisionEngineFailed::refused('write_failed_due_to_invalid_input');
            }
            $tuples[$tuple->toString()] = $tuple;
        }
        // All or nothing: the store changes only once every tuple has been accepted.
        $this->tuples[$store->value] = $tuples;
    }

    #[\Override]
    public function check(StoreId $store, AuthorizationModelId $model, AccessCheck $check): bool
    {
        $this->reachable();
        ++$this->questions;
        $relations = $this->modelOf($store, $model);
        self::relationOf($relations, $check->object->type, $check->relation);

        return $this->holds($store, $relations, $check->object, $check->relation, $check->subject, []);
    }

    #[\Override]
    public function batchCheck(StoreId $store, AuthorizationModelId $model, array $checks): array
    {
        return array_map(fn (AccessCheck $check): bool => $this->check($store, $model, $check), $checks);
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
        $this->reachable();
        ++$this->questions;
        $relations = $this->modelOf($store, $model);
        self::relationOf($relations, $type, $relation);

        // Only an object some tuple names can be related to anything.
        $found = [];
        foreach ($this->tuples[$store->value] as $tuple) {
            $object = $tuple->object;
            if (! $object->type->equals($type) || isset($found[$object->toString()])) {
                continue;
            }
            if ($this->holds($store, $relations, $object, $relation, $subject, [])) {
                $found[$object->toString()] = $object;
            }
        }

        return array_values($found);
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
        $this->reachable();
        ++$this->questions;
        $relations = $this->modelOf($store, $model);
        self::relationOf($relations, $object->type, $relation);

        // Only a subject some tuple names can hold anything.
        $found = [];
        foreach ($this->tuples[$store->value] as $tuple) {
            $candidate = $tuple->subject;
            if ($candidate->isUserset() || ! $candidate->object->type->equals($subjectType)) {
                continue;
            }
            $key = $candidate->object->toString();
            if (! isset($found[$key]) && $this->holds($store, $relations, $object, $relation, $candidate, [])) {
                $found[$key] = $candidate->object;
            }
        }

        return array_values($found);
    }

    #[\Override]
    public function readBySubject(StoreId $store, SubjectRef $subject, ObjectType $objectType): array
    {
        $this->reachable();
        $this->storeOf($store);

        return array_values(array_filter(
            $this->tuples[$store->value],
            static fn (Tuple $tuple): bool => $tuple->subject->equals($subject)
                && $tuple->object->type->equals($objectType),
        ));
    }

    /**
     * Whether `subject` holds `relation` on `object`, as the model works it out.
     *
     * @param Relations $relations
     * @param array<string, true> $visiting What is being worked out already: a cycle answers no.
     */
    private function holds(
        StoreId $store,
        array $relations,
        ObjectRef $object,
        Relation $relation,
        SubjectRef $subject,
        array $visiting,
    ): bool {
        $here = $object->toString() . '#' . $relation->name;
        if (isset($visiting[$here])) {
            return false;
        }
        $visiting[$here] = true;
        $definition = $relations[$object->type->value][$relation->name] ?? null;
        if ($definition === null) {
            return false;
        }

        return $this->rewrite($store, $relations, $object, $relation, $definition['rewrite'], $subject, $visiting);
    }

    /**
     * @param Relations $relations
     * @param array<array-key, mixed> $rewrite
     * @param array<string, true> $visiting
     */
    private function rewrite(
        StoreId $store,
        array $relations,
        ObjectRef $object,
        Relation $relation,
        array $rewrite,
        SubjectRef $subject,
        array $visiting,
    ): bool {
        if (array_key_exists('this', $rewrite)) {
            foreach ($this->tuples[$store->value] as $tuple) {
                if (! $tuple->object->equals($object) || ! $tuple->relation->equals($relation)) {
                    continue;
                }
                if ($tuple->subject->equals($subject)) {
                    return true;
                }
                $through = $tuple->subject->relation;
                if (
                    $through !== null
                    && $this->holds($store, $relations, $tuple->subject->object, $through, $subject, $visiting)
                ) {
                    return true;
                }
            }

            return false;
        }
        if (isset($rewrite['computedUserset'])) {
            return $this->holds(
                $store,
                $relations,
                $object,
                Relation::fromString(self::relationName($rewrite['computedUserset'])),
                $subject,
                $visiting,
            );
        }
        if (isset($rewrite['tupleToUserset']) && is_array($rewrite['tupleToUserset'])) {
            $tupleset = Relation::fromString(self::relationName($rewrite['tupleToUserset']['tupleset'] ?? null));
            $computed = Relation::fromString(self::relationName($rewrite['tupleToUserset']['computedUserset'] ?? null));
            foreach ($this->tuples[$store->value] as $tuple) {
                if (
                    $tuple->object->equals($object)
                    && $tuple->relation->equals($tupleset)
                    && ! $tuple->subject->isUserset()
                    && $this->holds($store, $relations, $tuple->subject->object, $computed, $subject, $visiting)
                ) {
                    return true;
                }
            }

            return false;
        }
        /** @var array{union: array{child: list<array<array-key, mixed>>}} $rewrite Checked by relationsOf(). */
        foreach ($rewrite['union']['child'] as $child) {
            if ($this->rewrite($store, $relations, $object, $relation, $child, $subject, $visiting)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The model's relations, by type then name, or `invalid_authorization_model` as OpenFGA answers
     * a model that does not hold together.
     *
     * @return Relations
     */
    private static function relationsOf(AuthorizationModel $model): array
    {
        /** @var array{type_definitions: list<array<string, mixed>>, conditions?: mixed} $document */
        $document = json_decode($model->json, true, 64, JSON_THROW_ON_ERROR);
        if (($document['conditions'] ?? []) !== []) {
            throw new LogicException('The fake decision engine does not evaluate conditions.');
        }

        $relations = [];
        foreach ($document['type_definitions'] as $definition) {
            $type = (string) $definition['type'];
            $relations[$type] = [];
            /** @var array<string, array<array-key, mixed>> $declared */
            $declared = is_array($definition['relations'] ?? null) ? $definition['relations'] : [];
            /** @var array<string, array<string, mixed>> $metadata */
            /** @var array<string, array{directly_related_user_types?: list<mixed>}> $metadata */
            $metadata = $definition['metadata']['relations'] ?? [];
            foreach ($declared as $name => $rewrite) {
                $takes = [];
                /**
                 * OpenFGA's own shape for what a direct relation takes; the double trusts the test's model.
                 *
                 * @var list<array{type: string, relation?: string, wildcard?: mixed, condition?: mixed}> $direct
                 */
                $direct = $metadata[$name]['directly_related_user_types'] ?? [];
                foreach ($direct as $taken) {
                    if (isset($taken['wildcard']) || isset($taken['condition'])) {
                        throw new LogicException('The fake decision engine does not evaluate wildcards or conditions.');
                    }
                    $takes[] = $taken['type'] . (isset($taken['relation']) ? '#' . $taken['relation'] : '');
                }
                $relations[$type][$name] = ['rewrite' => $rewrite, 'takes' => $takes];
            }
        }

        foreach ($relations as $type => $byName) {
            foreach ($byName as $definition) {
                self::validate($relations, $type, $definition['rewrite'], $definition['takes']);
            }
        }

        return $relations;
    }

    /**
     * @param Relations $relations
     * @param array<array-key, mixed> $rewrite
     * @param list<string> $takes
     */
    private static function validate(array $relations, string $type, array $rewrite, array $takes): void
    {
        if (array_key_exists('this', $rewrite)) {
            if ($takes === []) {
                throw DecisionEngineFailed::refused('invalid_authorization_model');
            }
            foreach ($takes as $taken) {
                $takenType = explode('#', $taken, 2)[0];
                $takenRelation = explode('#', $taken, 2)[1] ?? null;
                if (
                    ! isset($relations[$takenType])
                    || ($takenRelation !== null && ! isset($relations[$takenType][$takenRelation]))
                ) {
                    throw DecisionEngineFailed::refused('invalid_authorization_model');
                }
            }

            return;
        }
        if (isset($rewrite['computedUserset'])) {
            if (! isset($relations[$type][self::relationName($rewrite['computedUserset'])])) {
                throw DecisionEngineFailed::refused('invalid_authorization_model');
            }

            return;
        }
        if (isset($rewrite['tupleToUserset']) && is_array($rewrite['tupleToUserset'])) {
            $tupleset = self::relationName($rewrite['tupleToUserset']['tupleset'] ?? null);
            if (! isset($relations[$type][$tupleset])) {
                throw DecisionEngineFailed::refused('invalid_authorization_model');
            }

            return;
        }
        $children = is_array($rewrite['union'] ?? null) ? ($rewrite['union']['child'] ?? null) : null;
        if (! is_array($children) || $children === []) {
            throw new LogicException(
                'The fake decision engine works out unions of direct, computed and parent relations only.',
            );
        }
        /** @var mixed $child */
        foreach ($children as $child) {
            self::validate($relations, $type, is_array($child) ? $child : [], $takes);
        }
    }

    /**
     * Whether the model takes the tuple: its type declared, the relation on it direct, and the
     * subject one of the types or usersets the relation takes. Otherwise `validation_error`.
     *
     * @param Relations $relations
     */
    private static function allowed(array $relations, Tuple $tuple): void
    {
        $definition = self::relationOf($relations, $tuple->object->type, $tuple->relation);
        $subject = $tuple->subject->object->type->value
            . ($tuple->subject->relation === null ? '' : '#' . $tuple->subject->relation->name);
        if (! in_array($subject, $definition['takes'], true)) {
            throw DecisionEngineFailed::refused('validation_error');
        }
    }

    /**
     * @param Relations $relations
     *
     * @return Definition
     */
    private static function relationOf(array $relations, ObjectType $type, Relation $relation): array
    {
        return $relations[$type->value][$relation->name] ?? throw DecisionEngineFailed::refused('validation_error');
    }

    private static function relationName(mixed $userset): string
    {
        $name = is_array($userset) ? ($userset['relation'] ?? null) : null;
        if (! is_string($name)) {
            throw DecisionEngineFailed::refused('validation_error');
        }

        return $name;
    }

    /** @return Relations */
    private function modelOf(StoreId $store, AuthorizationModelId $model): array
    {
        return $this->storeOf($store)[$model->value]
            ?? throw DecisionEngineFailed::refused('authorization_model_not_found');
    }

    /** @return array<string, Relations> */
    private function storeOf(StoreId $store): array
    {
        return $this->models[$store->value] ?? throw DecisionEngineFailed::refused('store_id_not_found');
    }

    private function reachable(): void
    {
        if ($this->unavailable) {
            throw DecisionEngineFailed::unavailable();
        }
    }

    /** A ULID the engine might have issued: increasing, like OpenFGA's. */
    private function nextUlid(): string
    {
        return '01' . str_pad((string) ++$this->ids, 24, '0', STR_PAD_LEFT);
    }
}
