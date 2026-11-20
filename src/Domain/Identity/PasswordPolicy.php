<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\InvalidValue;

/**
 * What a password chosen for an account must be.
 *
 * Length only, after NIST SP 800-63B §5.1.1: at least 8 characters, no composition
 * rules. The maximum is not a policy but the hash's: bcrypt reads 72 bytes, and a
 * longer password would silently be equal to every other one sharing its first 72.
 */
final class PasswordPolicy
{
    public const int MIN_LENGTH = 8;

    public const int MAX_BYTES = 72;

    private function __construct()
    {
    }

    /**
     * @return non-empty-string
     *
     * @throws InvalidValue When the password is shorter than 8 characters, longer than 72 bytes,
     *                      not UTF-8, or holds a NUL byte.
     */
    public static function accept(#[\SensitiveParameter] string $password): string
    {
        if (
            ! mb_check_encoding($password, 'UTF-8')
            || mb_strlen($password, 'UTF-8') < self::MIN_LENGTH
            || strlen($password) > self::MAX_BYTES
            || str_contains($password, "\0")
        ) {
            throw new InvalidValue(sprintf(
                'A password has at least %d characters and at most %d bytes.',
                self::MIN_LENGTH,
                self::MAX_BYTES,
            ));
        }
        assert($password !== '');

        return $password;
    }
}
