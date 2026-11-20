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
 * The name of an external identity provider: `google`, `github`. It appears in URLs
 * (`/auth/social/{name}`) and keys every identity linked through the provider, so it is
 * kept to lower-case letters, digits and dashes, starting with a letter.
 */
final readonly class ProviderName
{
    private const string PATTERN = '/^[a-z][a-z0-9-]{0,31}$/D';

    /**
     * @param non-empty-string $value
     */
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue
     */
    public static function fromString(string $value): self
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue(
                'A provider name is 1 to 32 characters among a-z, 0-9 and "-", starting with a letter.',
            );
        }
        assert($value !== '');

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
