<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * The code a person types to approve a device (RFC 8628 §3.2, §6.1): eight letters in
 * two groups, `BCDF-GHJK`.
 *
 * Deliberately low-entropy, because a person reads it off a television and types it on a
 * phone: twenty consonants (RFC 8628 §6.1: no vowels, so no words; none of the letters
 * people confuse with digits), eight of them — 20⁸, about 34 bits. What keeps it from
 * being guessed is its short life and that typing it achieves nothing without a session
 * here to approve with.
 */
final readonly class UserCode
{
    public const string ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

    private const int LENGTH = 8;

    private function __construct(public string $value)
    {
    }

    public static function generate(RandomSource $random): self
    {
        $characters = '';
        for ($i = 0; $i < self::LENGTH; ++$i) {
            $characters .= self::ALPHABET[$random->integer(0, strlen(self::ALPHABET) - 1)];
        }

        return new self(substr($characters, 0, 4) . '-' . substr($characters, 4));
    }

    /**
     * What a person typed, as the code it stands for: case, spaces, the dash or its
     * absence are not a different code.
     *
     * @throws InvalidValue When what is left is not eight letters of the alphabet.
     */
    public static function fromTyped(string $typed): self
    {
        $cleaned = strtoupper((string) preg_replace('/[\s\-]+/', '', $typed));
        if (strlen($cleaned) !== self::LENGTH || strspn($cleaned, self::ALPHABET) !== self::LENGTH) {
            throw new InvalidValue('A user code is eight letters, like BCDF-GHJK.');
        }

        return new self(substr($cleaned, 0, 4) . '-' . substr($cleaned, 4));
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
