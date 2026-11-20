<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;

/**
 * One permission an API defines: a scope value and what it allows, in words.
 *
 * A permission is a value *on an API*: `read:users` on two APIs are two permissions
 * that happen to be spelled the same, which is why a resource server checks `aud`
 * before it looks at `scope`.
 */
final readonly class Permission
{
    public const int MAX_VALUE_LENGTH = 128;

    private const int MAX_DESCRIPTION_LENGTH = 500;

    private function __construct(
        public Scope $value,
        public string $description,
    ) {
    }

    /**
     * @throws InvalidValue When the value is not a scope token of at most 128 characters, or the
     *                      description is longer than 500 characters or holds a control character.
     */
    public static function of(string $value, string $description = ''): self
    {
        if (strlen($value) > self::MAX_VALUE_LENGTH) {
            throw new InvalidValue('A permission is at most 128 characters.');
        }

        if (
            ! mb_check_encoding($description, 'UTF-8')
            || mb_strlen($description, 'UTF-8') > self::MAX_DESCRIPTION_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $description) === 1
        ) {
            throw new InvalidValue('A permission description is at most 500 characters of text on one line.');
        }

        return new self(Scope::fromString($value), $description);
    }
}
