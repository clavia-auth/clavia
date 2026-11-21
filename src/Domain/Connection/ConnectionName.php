<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

use Clavia\Domain\Shared\InvalidValue;

/**
 * The name of a connection — a way to sign in: `password`, `email`, `google`, `github`, a
 * pool or an OpenID Connect provider an operator named.
 *
 * The natural key, and permanent: sessions and accounts record it, every identity linked
 * through an external connection is keyed by it, and it is part of the callback URL
 * registered at the provider (`/auth/social/{name}/callback`). So it is kept to lower-case
 * letters, digits and dashes, starting with a letter.
 */
final readonly class ConnectionName
{
    public const string DEFAULT_POOL = 'password';

    /** The built-in passwordless connection: accounts proven by access to a mailbox. */
    public const string EMAIL = 'email';

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
                'A connection name is 1 to 32 characters among a-z, 0-9 and "-", starting with a letter.',
            );
        }
        assert($value !== '');

        return new self($value);
    }

    /**
     * The default database connection: the pool accounts land in when nothing else is
     * said, and the one existing accounts were moved into.
     */
    public static function defaultPool(): self
    {
        return new self(self::DEFAULT_POOL);
    }

    /** The passwordless connection, which every account signing in by email belongs to. */
    public static function email(): self
    {
        return new self(self::EMAIL);
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
