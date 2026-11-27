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
 * The name of a relation in an authorization model: `viewer`, `parent`, `member`.
 *
 * Held to OpenFGA's rule (1 to 50 characters, none of `:`, `#`, `@` or a space), and no
 * control character.
 */
final readonly class Relation
{
    private const string PATTERN = '/^[^:#@\s\x00-\x1F\x7F]{1,50}$/D';

    private function __construct(public string $name)
    {
    }

    /**
     * @throws InvalidValue When the name is empty, longer than 50 characters, or holds `:`, `#`,
     *                      `@`, a space or a control character.
     */
    public static function fromString(string $name): self
    {
        if (preg_match(self::PATTERN, $name) !== 1) {
            throw new InvalidValue('A relation is 1 to 50 characters, without ":", "#", "@" or a space.');
        }

        return new self($name);
    }

    public function equals(self $other): bool
    {
        return $this->name === $other->name;
    }
}
