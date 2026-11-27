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
 * One object of an authorization model, `type:id`: `document:42`, `user:3f2b8c1e-…`.
 *
 * The id is the owner's to choose (an API's own identifiers; a Clavia user's id, never an
 * address), held to OpenFGA's rules: no `#`, `:` or space, and the whole at most 256
 * characters. The id `*` is refused: OpenFGA reads it as every object of the type (a
 * wildcard), which nothing here means to say.
 */
final readonly class ObjectRef
{
    public const int MAX_LENGTH = 256;

    private const string ID_PATTERN = '/^[^#:\s\x00-\x1F\x7F]+$/D';

    private function __construct(
        public ObjectType $type,
        public string $id,
    ) {
    }

    /**
     * @throws InvalidValue When the id is empty, `*`, holds `#`, `:`, a space or a control
     *                      character, or the object is longer than 256 characters.
     */
    public static function of(ObjectType $type, string $id): self
    {
        if (preg_match(self::ID_PATTERN, $id) !== 1 || $id === '*') {
            throw new InvalidValue('An object id is not empty, not "*", and holds no "#", ":" or space.');
        }
        if (strlen($type->value) + 1 + strlen($id) > self::MAX_LENGTH) {
            throw new InvalidValue('An object is at most 256 characters.');
        }

        return new self($type, $id);
    }

    /**
     * The object written `type:id`, as OpenFGA writes it.
     *
     * @throws InvalidValue When it is not one type, a colon and an id, each valid.
     */
    public static function fromString(string $value): self
    {
        $parts = explode(':', $value);
        if (count($parts) !== 2) {
            throw new InvalidValue('An object is written "type:id".');
        }

        return self::of(ObjectType::fromString($parts[0]), $parts[1]);
    }

    public function toString(): string
    {
        return $this->type->value . ':' . $this->id;
    }

    public function equals(self $other): bool
    {
        return $this->type->equals($other->type) && $this->id === $other->id;
    }
}
