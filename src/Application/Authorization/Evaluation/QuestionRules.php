<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\ReservedType;
use Clavia\Domain\Shared\InvalidValue;

/**
 * What a question to the Authorization API may name (docs/design/fine-grained-authorization.md §5.2,
 * step 3), for an evaluation and a search alike: a subject that is a person (`user`) or an application
 * (`client`) the model declares; a resource of a type the model declares and that can be related to;
 * an action that is a relation of that type; and no `context.clavia`, which is Clavia's to write.
 * Each refusal is an {@see EvaluationRefused}: a `400`.
 */
final readonly class QuestionRules
{
    private function __construct()
    {
    }

    /** @throws EvaluationRefused */
    public static function subjectType(AuthorizationModel $model, string $type): ObjectType
    {
        $kind = ReservedType::tryFrom($type);
        if ($kind === null || ! $kind->isSubjectOnly()) {
            throw EvaluationRefused::subjectKind();
        }
        $declared = ObjectType::fromString($type);
        if (! $model->declares($declared)) {
            throw EvaluationRefused::unknownType();
        }

        return $declared;
    }

    /** @throws EvaluationRefused */
    public static function resourceType(AuthorizationModel $model, string $type): ObjectType
    {
        try {
            $declared = ObjectType::fromString($type);
        } catch (InvalidValue) {
            throw EvaluationRefused::malformed();
        }
        if (! $model->declares($declared) || ReservedType::of($declared)?->isSubjectOnly() === true) {
            throw EvaluationRefused::unknownType();
        }

        return $declared;
    }

    /** @throws EvaluationRefused */
    public static function relation(AuthorizationModel $model, ObjectType $type, string $action): Relation
    {
        try {
            $relation = Relation::fromString($action);
        } catch (InvalidValue) {
            throw EvaluationRefused::malformed();
        }
        if (! $model->relates($type, $relation)) {
            throw EvaluationRefused::unknownRelation();
        }

        return $relation;
    }

    /** @throws EvaluationRefused */
    public static function object(ObjectType $type, string $id): ObjectRef
    {
        try {
            return ObjectRef::of($type, $id);
        } catch (InvalidValue) {
            throw EvaluationRefused::malformed();
        }
    }

    /**
     * @param array<string, mixed> $context
     *
     * @throws EvaluationRefused
     */
    public static function context(array $context): void
    {
        if (array_key_exists('clavia', $context)) {
            throw EvaluationRefused::claviaContext();
        }
    }
}
