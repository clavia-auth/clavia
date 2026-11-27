<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use InvalidArgumentException;

/**
 * The engine that works out relationship-based decisions (docs/design/fine-grained-authorization.md
 * §2, §4): OpenFGA, beside Clavia, or another that speaks the same model.
 *
 * Each API with authorization on has a store of its own: its model's versions and its
 * relationships, which no question crosses. Every answer is strongly consistent (OpenFGA runs
 * with its caches off): a relationship written or deleted is seen by the next question.
 *
 * Every method throws {@see DecisionEngineFailed} when the engine gives no answer, and nothing
 * here ever stands in for one: a caller that catches it denies.
 */
interface DecisionEngine
{
    /** The most tuples one {@see self::write()} takes, writes and deletes together (OpenFGA's default). */
    public const int MAX_WRITES = 100;

    /**
     * A new, empty store.
     *
     * @param string $name What the engine shows of it: 3 to 64 letters, digits, spaces and
     *                     `.-/^_&@` (OpenFGA's rule).
     *
     * @throws DecisionEngineFailed
     */
    public function createStore(string $name): StoreId;

    /**
     * The store, its models and its relationships, gone from the engine's listings.
     *
     * OpenFGA's deletion is soft: the store is no longer found, but questions and writes naming
     * its id are still answered from what it held. Whoever deletes a store forgets its id in the
     * same step, and never asks with it again.
     *
     * @throws DecisionEngineFailed
     */
    public function deleteStore(StoreId $store): void;

    /**
     * A new version of the store's model. Earlier versions are kept, and the store's
     * relationships with them.
     *
     * @throws DecisionEngineFailed When the engine refuses the model (`refusal` says why).
     */
    public function writeModel(StoreId $store, AuthorizationModel $model): AuthorizationModelId;

    /**
     * Relationships written and deleted, all of them or none: a tuple the model does not allow,
     * one already written, or a deletion of one that is not, refuses the whole request.
     *
     * @param list<Tuple> $writes
     * @param list<Tuple> $deletes
     *
     * @throws InvalidArgumentException When there are more than {@see self::MAX_WRITES} together.
     * @throws DecisionEngineFailed
     */
    public function write(StoreId $store, AuthorizationModelId $model, array $writes, array $deletes = []): void;

    /**
     * Whether the check's subject holds its relation on its object, directly, through another
     * relation, or through a related object, as the model says.
     *
     * @throws DecisionEngineFailed
     */
    public function check(StoreId $store, AuthorizationModelId $model, AccessCheck $check): bool;

    /**
     * Each check's answer, in the order asked. Any number may be asked: the engine's own limit
     * per request is the adapter's to respect.
     *
     * @param list<AccessCheck> $checks
     *
     * @return list<bool>
     *
     * @throws DecisionEngineFailed When any one of them gets no answer.
     */
    public function batchCheck(StoreId $store, AuthorizationModelId $model, array $checks): array;

    /**
     * The objects of `type` the subject holds `relation` on, in no particular order, up to the
     * engine's own cap.
     *
     * @param array<string, mixed> $context
     *
     * @return list<ObjectRef>
     *
     * @throws DecisionEngineFailed
     */
    public function listObjects(
        StoreId $store,
        AuthorizationModelId $model,
        ObjectType $type,
        Relation $relation,
        SubjectRef $subject,
        array $context = [],
    ): array;

    /**
     * The objects of `subjectType` (people, applications) holding `relation` on `object`, in no
     * particular order, up to the engine's own cap.
     *
     * @param array<string, mixed> $context
     *
     * @return list<ObjectRef>
     *
     * @throws DecisionEngineFailed
     */
    public function listUsers(
        StoreId $store,
        AuthorizationModelId $model,
        ObjectRef $object,
        Relation $relation,
        ObjectType $subjectType,
        array $context = [],
    ): array;

    /**
     * Every relationship written with exactly this subject on an object of `objectType`, as
     * written (nothing worked out): what deleting a person or an application must remove.
     *
     * @return list<Tuple>
     *
     * @throws DecisionEngineFailed
     */
    public function readBySubject(StoreId $store, SubjectRef $subject, ObjectType $objectType): array;
}
