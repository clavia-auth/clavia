<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Shared\InvalidValue;

/**
 * Who or what a relationship is with: an object (`user:3f2b…`, `client:reports-app`,
 * `folder:7` as a document's parent), or a userset, every subject holding a relation on an
 * object (`team:sales#member`).
 *
 * Wildcards (`user:*`) are not subjects here: {@see ObjectRef} refuses the id `*`.
 */
final readonly class SubjectRef
{
    private function __construct(
        public ObjectRef $object,
        public ?Relation $relation,
    ) {
    }

    /** The object itself. */
    public static function object(ObjectRef $object): self
    {
        return new self($object, null);
    }

    /** Every subject holding `relation` on `object`: `team:sales#member`. */
    public static function userset(ObjectRef $object, Relation $relation): self
    {
        return new self($object, $relation);
    }

    /**
     * The subject written `type:id` or `type:id#relation`, as OpenFGA writes it.
     *
     * @throws InvalidValue When it is neither.
     */
    public static function fromString(string $value): self
    {
        $parts = explode('#', $value);

        return match (count($parts)) {
            1 => self::object(ObjectRef::fromString($parts[0])),
            2 => self::userset(ObjectRef::fromString($parts[0]), Relation::fromString($parts[1])),
            default => throw new InvalidValue('A subject is written "type:id" or "type:id#relation".'),
        };
    }

    public function isUserset(): bool
    {
        return $this->relation !== null;
    }

    public function toString(): string
    {
        return $this->object->toString() . ($this->relation === null ? '' : '#' . $this->relation->name);
    }

    public function equals(self $other): bool
    {
        return $this->toString() === $other->toString();
    }
}
