<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use DateTimeZone;
use LogicException;

/**
 * One version of an authorization model. Versions are immutable: writing a model makes a new one.
 *
 * The decision engine names it; OpenFGA's ids are ULIDs (26 characters of Crockford's
 * base 32), and the rule is held here so an id read back from storage or a request is one the
 * engine could have issued.
 */
final readonly class AuthorizationModelId
{
    private const string CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    private const string PATTERN = '/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/D';

    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value is not a ULID in upper case.
     */
    public static function fromString(string $value): self
    {
        if (preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue('An identifier of the decision engine is a ULID such as 01HZX3…');
        }

        return new self($value);
    }

    /**
     * When the engine made the version: a ULID's first ten characters are its millisecond since the
     * Unix epoch, in Crockford's base 32 (https://github.com/ulid/spec).
     */
    public function createdAt(): DateTimeImmutable
    {
        $milliseconds = 0;
        foreach (str_split(substr($this->value, 0, 10)) as $character) {
            $milliseconds = $milliseconds * 32 + (int) strpos(self::CROCKFORD, $character);
        }
        $instant = DateTimeImmutable::createFromFormat(
            'U.v',
            sprintf('%d.%03d', intdiv($milliseconds, 1000), $milliseconds % 1000),
            new DateTimeZone('UTC'),
        );

        return $instant ?: throw new LogicException('A ULID\'s time is an instant.');
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
