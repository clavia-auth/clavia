<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;

/**
 * One question for the {@see DecisionEngine}: does `subject` hold `relation` on `object`?
 *
 * The context is what the model's conditions may read (OpenFGA's check context, CEL): a JSON
 * object, passed to the engine as it is.
 */
final readonly class AccessCheck
{
    /**
     * @param array<string, mixed> $context
     */
    private function __construct(
        public ObjectRef $object,
        public Relation $relation,
        public SubjectRef $subject,
        public array $context,
    ) {
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function of(ObjectRef $object, Relation $relation, SubjectRef $subject, array $context = []): self
    {
        return new self($object, $relation, $subject, $context);
    }
}
