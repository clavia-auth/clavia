<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Domain\Authentication;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * The six digits of a passwordless sign-in by code.
 *
 * Deliberately short, because a person reads it in an email and types it: 10⁶ values.
 * What keeps it from being guessed is that it answers one challenge held by one browser,
 * for a few minutes, with a small budget of wrong answers
 * ({@see PasswordlessChallenge}).
 */
final readonly class OneTimeCode
{
    private const int DIGITS = 6;

    /**
     * @param string $value Six digits, leading zeros included.
     */
    private function __construct(#[\SensitiveParameter] public string $value)
    {
    }

    public static function generate(RandomSource $random): self
    {
        return new self(sprintf('%06d', $random->integer(0, 10 ** self::DIGITS - 1)));
    }

    /**
     * What a person typed, as the code it stands for: spaces and dashes — "123 456", as
     * the email may be read aloud — are not a different code.
     *
     * @throws InvalidValue When what is left is not six digits.
     */
    public static function fromTyped(#[\SensitiveParameter] string $typed): self
    {
        $cleaned = (string) preg_replace('/[\s\-]+/u', '', $typed);
        if (strlen($cleaned) !== self::DIGITS || ! ctype_digit($cleaned)) {
            throw new InvalidValue('A sign-in code is six digits.');
        }

        return new self($cleaned);
    }
}
