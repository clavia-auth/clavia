<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Rbac;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The identifier of a role: `rol_` and 16 letters and digits.
 *
 * Generated rather than the name: operators rename roles, and the assignments and the
 * URLs that point at one must not follow a typo fix.
 */
final readonly class RoleId
{
    private const string PREFIX = 'rol';

    /** @param non-empty-string $value */
    private function __construct(public string $value)
    {
    }

    public static function generate(SecretGenerator $secrets): self
    {
        return new self($secrets->prefixedId(self::PREFIX));
    }

    /**
     * @throws InvalidValue When the value is not `rol_` followed by 16 letters and digits.
     */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match('/^rol_[A-Za-z0-9]{16}$/D', $value) !== 1) {
            throw new InvalidValue('A role id is "rol_" followed by 16 letters and digits.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
