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
 * The type of an object in an authorization model: `document`, `folder`, `user`.
 *
 * Held to OpenFGA's rule for a type name (1 to 254 characters, none of `:`, `#`, `@` or a
 * space), and no control character, so a name that exists here is one the engine accepts and
 * one that cannot be read as part of an object, a userset or a subject.
 */
final readonly class ObjectType
{
    private const string PATTERN = '/^[^:#@\s\x00-\x1F\x7F]{1,254}$/D';

    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the name is empty, longer than 254 characters, or holds `:`, `#`,
     *                      `@`, a space or a control character.
     */
    public static function fromString(string $value): self
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue('A type is 1 to 254 characters, without ":", "#", "@" or a space.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
