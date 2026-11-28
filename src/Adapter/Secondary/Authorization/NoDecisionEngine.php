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
use Clavia\Application\Port\TuplePage;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;

/**
 * The {@see DecisionEngine} when `CLAVIA_FGA_URL` is unset: fine-grained authorization is off, no
 * route reaches an engine, and anything that asks one anyway is told it is unavailable, which
 * is never a decision.
 */
final readonly class NoDecisionEngine implements DecisionEngine
{
    #[\Override]
    public function createStore(string $name): StoreId
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function deleteStore(StoreId $store): void
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function writeModel(StoreId $store, AuthorizationModel $model): AuthorizationModelId
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function write(StoreId $store, AuthorizationModelId $model, array $writes, array $deletes = []): void
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function check(StoreId $store, AuthorizationModelId $model, AccessCheck $check): bool
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function batchCheck(StoreId $store, AuthorizationModelId $model, array $checks): array
    {
        throw DecisionEngineFailed::unavailable();
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
        throw DecisionEngineFailed::unavailable();
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
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function readBySubject(StoreId $store, SubjectRef $subject, ObjectType $objectType): array
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function readByObject(StoreId $store, ObjectRef $object): array
    {
        throw DecisionEngineFailed::unavailable();
    }

    #[\Override]
    public function readPage(StoreId $store, ObjectRef $object, int $pageSize, string $continuation = ''): TuplePage
    {
        throw DecisionEngineFailed::unavailable();
    }
}
