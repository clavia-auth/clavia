<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * One scope token (RFC 6749 §3.3): `openid`, `read:users`.
 *
 * A scope on its own names nothing: `read:users` on two different APIs are two
 * different permissions. It only means something next to an {@see Audience}.
 */
final readonly class Scope
{
    /** scope-token = 1*NQCHAR — printable ASCII except space, double quote and backslash. */
    private const string PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

    /**
     * @param non-empty-string $value
     */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the token is empty or holds a character RFC 6749 forbids.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue(
                'A scope is one or more printable ASCII characters other than space, double quote and backslash.',
            );
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
