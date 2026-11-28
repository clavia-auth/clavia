<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

/**
 * A relationship: `subject` holds `relation` on `object`. OpenFGA calls it a relationship
 * tuple, and Zanzibar a relation tuple: `document:42#viewer@user:3f2b…`.
 *
 * It says nothing of whether the model allows it; the decision engine refuses a tuple its model
 * does not (a type it does not declare, a relation the type lacks, a subject the relation does
 * not take, a condition it does not declare or the relation does not take).
 *
 * A relationship is one per object, relation and subject: its condition, if any, is not part of what
 * it is, so {@see self::toString()} and {@see self::equals()} leave it out, as OpenFGA does.
 */
final readonly class Tuple
{
    private function __construct(
        public ObjectRef $object,
        public Relation $relation,
        public SubjectRef $subject,
        public ?Condition $condition = null,
    ) {
    }

    public static function of(
        ObjectRef $object,
        Relation $relation,
        SubjectRef $subject,
        ?Condition $condition = null,
    ): self {
        return new self($object, $relation, $subject, $condition);
    }

    /** `object#relation@subject`, Zanzibar's notation: for messages and comparison. */
    public function toString(): string
    {
        return $this->object->toString() . '#' . $this->relation->name . '@' . $this->subject->toString();
    }

    public function equals(self $other): bool
    {
        return $this->toString() === $other->toString();
    }
}
