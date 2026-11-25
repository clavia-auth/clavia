<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * The `ID` of an `AuthnRequest` this server sent, which the response must name back
 * (`InResponseTo`, SAML Profiles §4.1.4.2): `_` and 32 random bytes in hex. The schema's `ID` is an
 * `xs:ID`, an NCName, which cannot start with a digit: hence the underscore.
 */
final readonly class SamlRequestId
{
    private const string PATTERN = '/^_[0-9a-f]{64}$/D';

    /** @param non-empty-string $value */
    private function __construct(public string $value)
    {
    }

    public static function generate(RandomSource $random): self
    {
        return new self('_' . bin2hex($random->bytes(32)));
    }

    /** @throws InvalidValue */
    public static function fromString(string $value): self
    {
        if ($value === '' || preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue('A SAML request id is "_" and 64 hexadecimal digits.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }
}
