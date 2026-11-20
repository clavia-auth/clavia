<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

use Clavia\Domain\Shared\InvalidValue;

/**
 * The `nonce` of an authentication request (OIDC Core §3.1.2.1): a value the relying
 * party ties to its own session and expects back, verbatim, in the ID token.
 *
 * The specification sets no length or alphabet. A bound is set here anyway, because
 * the value is stored with the code and copied into a signed token: at most 512 bytes,
 * and no control character — nothing a legitimate relying party generates, everything
 * a hostile one could use to bloat tokens or smuggle line breaks into logs.
 */
final readonly class Nonce
{
    public const int MAX_LENGTH = 512;

    /** @param non-empty-string $value */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value is empty, longer than 512 bytes, not UTF-8, or holds a
     *                      control character.
     */
    public static function fromString(string $value): self
    {
        if (
            $value === ''
            || strlen($value) > self::MAX_LENGTH
            || ! mb_check_encoding($value, 'UTF-8')
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new InvalidValue('A nonce is 1 to 512 bytes of UTF-8 text with no control characters.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
