<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\InvalidValue;

/**
 * What a person calls a passkey ("Work laptop"): one to sixty-four characters, so they can tell
 * their passkeys apart on the account page.
 *
 * Printed back to its owner and to an operator, never interpreted; control characters are
 * refused so a name cannot reshape a line or a log entry.
 */
final readonly class PasskeyName
{
    public const int MAX_LENGTH = 64;

    private function __construct(public string $value)
    {
    }

    /**
     * Surrounding whitespace is dropped, not refused.
     *
     * @throws InvalidValue When nothing is left, it is longer than 64 characters, is not valid
     *                      UTF-8, or holds a control character.
     */
    public static function fromString(string $value): self
    {
        $value = trim($value);
        if ($value === '' || ! mb_check_encoding($value, 'UTF-8')) {
            throw new InvalidValue('A passkey needs a name of one to 64 characters.');
        }
        if (mb_strlen($value) > self::MAX_LENGTH) {
            throw new InvalidValue(sprintf("A passkey's name is at most %d characters.", self::MAX_LENGTH));
        }
        if (preg_match('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', $value) === 1) {
            throw new InvalidValue("A passkey's name holds no control characters.");
        }

        return new self($value);
    }
}
