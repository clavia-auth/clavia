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
 * The identifier of the API a token is for: its `aud`.
 *
 * An identifier, not a location — usually written as a URL, never dereferenced, and
 * compared byte for byte: `https://api.example/` and `https://api.example` are two
 * different audiences. Checked before any scope is, because a scope means nothing
 * without the API it belongs to.
 */
final readonly class Audience
{
    private const int MAX_LENGTH = 2048;

    /**
     * @param non-empty-string $value
     */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the identifier is empty, too long, or holds whitespace or a control character.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || strlen($value) > self::MAX_LENGTH || preg_match('/[\x00-\x20\x7F]/', $value) === 1) {
            throw new InvalidValue(
                'An audience is a non-empty identifier of at most 2048 bytes with no whitespace or control characters.',
            );
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
